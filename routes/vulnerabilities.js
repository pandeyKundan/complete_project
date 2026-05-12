const express = require('express');
const router = express.Router();
const { getDb, allQuery, getQuery, runQuery } = require('../config/database');

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

router.get('/', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { severity, status } = req.query;
        
        let sql = `SELECT v.*, s.target_url 
                   FROM vulnerabilities v 
                   JOIN scans s ON v.scan_id = s.id 
                   WHERE s.user_id = ?`;
        const params = [userId];
        
        if (severity && severity !== 'all') {
            sql += ` AND v.severity = ?`;
            params.push(severity);
        }
        if (status && status !== 'all') {
            sql += ` AND v.status = ?`;
            params.push(status);
        }
        
        sql += ` ORDER BY 
            CASE v.severity 
                WHEN 'critical' THEN 1 
                WHEN 'high' THEN 2 
                WHEN 'medium' THEN 3 
                ELSE 4 
            END, v.created_at DESC`;
        
        const vulnerabilities = await allQuery(sql, params);
        res.json(vulnerabilities || []);
    } catch (err) {
        console.error('Get vulnerabilities error:', err);
        res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
    }
});

router.get('/:id', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const vulnerability = await getQuery(
            `SELECT v.*, s.target_url 
             FROM vulnerabilities v 
             JOIN scans s ON v.scan_id = s.id 
             WHERE v.id = ? AND s.user_id = ?`,
            [req.params.id, userId]
        );
        
        if (!vulnerability) {
            return res.status(404).json({ error: 'Vulnerability not found' });
        }
        
        res.json(vulnerability);
    } catch (err) {
        console.error('Get vulnerability error:', err);
        res.status(500).json({ error: 'Failed to fetch vulnerability' });
    }
});

router.put('/:id/status', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { status } = req.body;
        
        if (!['open', 'fixed', 'false_positive'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const result = await runQuery(
            `UPDATE vulnerabilities 
             SET status = ? 
             WHERE id = ? AND EXISTS (
                 SELECT 1 FROM scans WHERE id = scan_id AND user_id = ?
             )`,
            [status, req.params.id, userId]
        );
        
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Vulnerability not found' });
        }
        
        res.json({ success: true });
    } catch (err) {
        console.error('Update vulnerability error:', err);
        res.status(500).json({ error: 'Failed to update vulnerability' });
    }
});

module.exports = router;
