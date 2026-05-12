const express = require('express');
const router = express.Router();
const { getDb, allQuery, runQuery, getQuery } = require('../config/database');
const { simulateScan } = require('../utils/scanSimulator');

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

router.post('/', isAuthenticated, async (req, res) => {
    try {
        const { targetUrl, scanType } = req.body;
        const userId = req.session.userId;
        
        if (!targetUrl || !scanType) {
            return res.status(400).json({ error: 'Target URL and scan type required' });
        }
        
        const db = getDb();
        
        const result = await runQuery(
            'INSERT INTO scans (user_id, target_url, scan_type, status, progress) VALUES (?, ?, ?, ?, ?)',
            [userId, targetUrl, scanType, 'pending', 0]
        );
        
        const scanId = result.lastID;
        
        simulateScan(scanId, targetUrl, scanType, db, async (scanId, title, description, severity, location, remediation) => {
            await runQuery(
                `INSERT INTO vulnerabilities (scan_id, title, description, severity, location, remediation) 
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [scanId, title, description, severity, location, remediation]
            );
        });
        
        res.json({ success: true, scanId });
    } catch (err) {
        console.error('Start scan error:', err);
        res.status(500).json({ error: 'Failed to start scan' });
    }
});

router.get('/:id', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const scan = await getQuery('SELECT * FROM scans WHERE id = ? AND user_id = ?', [req.params.id, userId]);
        
        if (!scan) {
            return res.status(404).json({ error: 'Scan not found' });
        }
        
        const vulnerabilities = await allQuery('SELECT * FROM vulnerabilities WHERE scan_id = ?', [req.params.id]);
        
        res.json({ ...scan, vulnerabilities });
    } catch (err) {
        console.error('Get scan error:', err);
        res.status(500).json({ error: 'Failed to fetch scan' });
    }
});

router.get('/', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const scans = await allQuery('SELECT * FROM scans WHERE user_id = ? ORDER BY started_at DESC', [userId]);
        res.json(scans || []);
    } catch (err) {
        console.error('Get scans error:', err);
        res.status(500).json({ error: 'Failed to fetch scans' });
    }
});

module.exports = router;
