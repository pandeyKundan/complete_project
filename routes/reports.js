const express = require('express');
const router = express.Router();
const { getDb, allQuery, runQuery, getQuery } = require('../config/database');

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

router.post('/generate', isAuthenticated, async (req, res) => {
    try {
        const { scanId, reportType, title } = req.body;
        const userId = req.session.userId;
        
        if (!scanId || !title) {
            return res.status(400).json({ error: 'Scan ID and title required' });
        }
        
        const scan = await getQuery('SELECT * FROM scans WHERE id = ? AND user_id = ?', [scanId, userId]);
        
        if (!scan) {
            return res.status(404).json({ error: 'Scan not found' });
        }
        
        const vulnerabilities = await allQuery('SELECT * FROM vulnerabilities WHERE scan_id = ?', [scanId]);
        
        const reportContent = {
            scan: {
                id: scan.id,
                targetUrl: scan.target_url,
                scanType: scan.scan_type,
                startedAt: scan.started_at,
                completedAt: scan.completed_at,
                durationSeconds: scan.duration_seconds,
                securityScore: scan.security_score
            },
            vulnerabilities: vulnerabilities,
            summary: {
                total: vulnerabilities.length,
                critical: vulnerabilities.filter(v => v.severity === 'critical').length,
                high: vulnerabilities.filter(v => v.severity === 'high').length,
                medium: vulnerabilities.filter(v => v.severity === 'medium').length,
                low: vulnerabilities.filter(v => v.severity === 'low').length
            },
            generatedAt: new Date().toISOString()
        };
        
        const result = await runQuery(
            'INSERT INTO reports (user_id, report_type, title, content) VALUES (?, ?, ?, ?)',
            [userId, reportType || 'scan', title, JSON.stringify(reportContent)]
        );
        
        res.status(201).json({ success: true, reportId: result.lastID });
        
    } catch (err) {
        console.error('Generate report error:', err);
        res.status(500).json({ error: 'Failed to generate report: ' + err.message });
    }
});

router.get('/', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const reports = await allQuery(
            'SELECT id, report_type, title, generated_at FROM reports WHERE user_id = ? ORDER BY generated_at DESC',
            [userId]
        );
        res.json(reports || []);
    } catch (err) {
        console.error('Get reports error:', err);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

router.get('/:id', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const report = await getQuery('SELECT * FROM reports WHERE id = ? AND user_id = ?', [req.params.id, userId]);
        
        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }
        
        if (report.content && typeof report.content === 'string') {
            try {
                report.content = JSON.parse(report.content);
            } catch (e) {}
        }
        
        res.json(report);
    } catch (err) {
        console.error('Get report error:', err);
        res.status(500).json({ error: 'Failed to fetch report' });
    }
});

module.exports = router;
