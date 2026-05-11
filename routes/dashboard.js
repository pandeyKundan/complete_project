const express = require('express');
const router = express.Router();
const { getQuery, allQuery } = require('../config/database');
const { getVulnerabilityStats, getRecentVulnerabilities } = require('../models/Vulnerability');
const { getRecentScans } = require('../models/Scan');

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

// GET /api/dashboard/stats - Main dashboard stats
router.get('/stats', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const vulnStats = await getVulnerabilityStats(userId);
        const recentScans = await getRecentScans(userId, 5);
        
        // Calculate security score
        let securityScore = 100;
        if (vulnStats.total > 0) {
            const criticalWeight = (vulnStats.critical || 0) * 20;
            const highWeight = (vulnStats.high || 0) * 10;
            const mediumWeight = (vulnStats.medium || 0) * 5;
            const totalWeight = criticalWeight + highWeight + mediumWeight;
            const maxWeight = (vulnStats.total || 1) * 20;
            securityScore = Math.max(0, Math.min(100, 100 - (totalWeight / maxWeight) * 100));
        }
        
        res.json({
            securityScore: Math.floor(securityScore),
            totalVulnerabilities: vulnStats.total || 0,
            criticalIssues: vulnStats.critical || 0,
            highIssues: vulnStats.high || 0,
            mediumIssues: vulnStats.medium || 0,
            lowIssues: vulnStats.low || 0,
            openIssues: vulnStats.open || 0,
            fixedIssues: vulnStats.fixed || 0,
            recentScans: recentScans.map(s => ({
                id: s.id,
                target_url: s.target_url,
                scan_type: s.scan_type,
                status: s.status,
                security_score: s.security_score,
                started_at: s.started_at,
                completed_at: s.completed_at
            }))
        });
        
    } catch (err) {
        console.error('Dashboard stats error:', err);
        res.status(500).json({ error: 'Failed to load dashboard stats' });
    }
});

// GET /api/dashboard/security-score - Security score only
router.get('/security-score', isAuthenticated, async (req, res) => {
    try {
        const vulnStats = await getVulnerabilityStats(req.session.userId);
        let score = 100;
        if (vulnStats.total > 0) {
            const criticalWeight = (vulnStats.critical || 0) * 20;
            const highWeight = (vulnStats.high || 0) * 10;
            const mediumWeight = (vulnStats.medium || 0) * 5;
            const totalWeight = criticalWeight + highWeight + mediumWeight;
            const maxWeight = (vulnStats.total || 1) * 20;
            score = Math.max(0, Math.min(100, 100 - (totalWeight / maxWeight) * 100));
        }
        res.json({ score: Math.floor(score) });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get security score' });
    }
});

// GET /api/dashboard/vulnerabilities - Vulnerability summary
router.get('/vulnerabilities', isAuthenticated, async (req, res) => {
    try {
        const stats = await getVulnerabilityStats(req.session.userId);
        res.json({
            total: stats.total || 0,
            critical: stats.critical || 0,
            high: stats.high || 0,
            medium: stats.medium || 0,
            low: stats.low || 0,
            open: stats.open || 0,
            fixed: stats.fixed || 0
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get vulnerabilities' });
    }
});

// GET /api/dashboard/recent-scans - Recent scans list
router.get('/recent-scans', isAuthenticated, async (req, res) => {
    try {
        const scans = await getRecentScans(req.session.userId, 5);
        res.json({ scans });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get recent scans' });
    }
});

// GET /api/dashboard/critical-issues - Critical issues list
router.get('/critical-issues', isAuthenticated, async (req, res) => {
    try {
        const issues = await allQuery(
            `SELECT v.id, v.title, v.description, v.severity, v.location, v.created_at, s.target_url
             FROM vulnerabilities v
             JOIN scans s ON v.scan_id = s.id
             WHERE s.user_id = ? AND v.severity = 'critical' AND v.status = 'open'
             ORDER BY v.created_at DESC
             LIMIT 10`,
            [req.session.userId]
        );
        res.json({ issues: issues || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get critical issues' });
    }
});

// GET /api/dashboard/chart-data - Chart data for dashboard
router.get('/chart-data', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        // Get weekly trend data
        const weeklyData = await allQuery(
            `SELECT 
                strftime('%w', v.created_at) as day,
                SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN v.severity = 'medium' THEN 1 ELSE 0 END) as medium
             FROM vulnerabilities v
             JOIN scans s ON v.scan_id = s.id
             WHERE s.user_id = ? AND v.created_at >= date('now', '-30 days')
             GROUP BY day
             ORDER BY day`,
            [userId]
        );
        
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const critical = new Array(7).fill(0);
        const high = new Array(7).fill(0);
        const medium = new Array(7).fill(0);
        
        weeklyData.forEach(row => {
            const dayIndex = parseInt(row.day);
            critical[dayIndex] = row.critical || 0;
            high[dayIndex] = row.high || 0;
            medium[dayIndex] = row.medium || 0;
        });
        
        // Severity distribution
        const stats = await getVulnerabilityStats(userId);
        
        res.json({
            vulnerability: {
                labels: days,
                datasets: [{
                    label: 'Vulnerabilities',
                    data: critical.map((c, i) => c + high[i] + medium[i]),
                    borderColor: '#2a75ff',
                    backgroundColor: 'rgba(42, 117, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            threat: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [stats.critical || 0, stats.high || 0, stats.medium || 0, stats.low || 0],
                    backgroundColor: ['#dc2626', '#f97316', '#fbbf24', '#22c55e']
                }]
            }
        });
        
    } catch (err) {
        console.error('Chart data error:', err);
        res.json({
            vulnerability: { labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], datasets: [{ data: [0,0,0,0,0,0,0] }] },
            threat: { labels: ['Critical', 'High', 'Medium', 'Low'], datasets: [{ data: [0,0,0,0] }] }
        });
    }
});

// GET /api/dashboard/trends - Trends data (for reports page)
router.get('/trends', isAuthenticated, async (req, res) => {
    try {
        const weeklyData = await allQuery(
            `SELECT 
                strftime('%w', v.created_at) as day,
                COUNT(*) as count
             FROM vulnerabilities v
             JOIN scans s ON v.scan_id = s.id
             WHERE s.user_id = ? AND v.created_at >= date('now', '-7 days')
             GROUP BY day`,
            [req.session.userId]
        );
        
        const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        const counts = new Array(7).fill(0);
        
        weeklyData.forEach(row => {
            let index = parseInt(row.day);
            if (index === 0) index = 6;
            else index = index - 1;
            counts[index] = row.count || 0;
        });
        
        res.json({
            labels: days,
            critical: counts,
            high: counts.map(c => Math.floor(c * 0.6)),
            medium: counts.map(c => Math.floor(c * 0.3))
        });
    } catch (err) {
        res.json({ labels: days, critical: [0,0,0,0,0,0,0], high: [0,0,0,0,0,0,0], medium: [0,0,0,0,0,0,0] });
    }
});

module.exports = router;
