const express = require('express');
const router = express.Router();
const { getDb, allQuery, getQuery } = require('../config/database');

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

// Get dashboard stats
router.get('/stats', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        console.log('📊 Fetching stats for user:', userId);
        
        // Get vulnerability statistics - CRITICAL
        const vulnStats = await getQuery(
            `SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
             FROM vulnerabilities v
             JOIN scans s ON v.scan_id = s.id
             WHERE s.user_id = ?`,
            [userId]
        );
        
        console.log('📊 Vulnerability stats:', vulnStats);
        
        // Get total scans count
        const scansCount = await getQuery(
            'SELECT COUNT(*) as total FROM scans WHERE user_id = ?',
            [userId]
        );
        
        // Get recent scans
        const recentScans = await allQuery(
            `SELECT id, target_url, scan_type, status, started_at, duration_seconds, security_score
             FROM scans 
             WHERE user_id = ? 
             ORDER BY started_at DESC 
             LIMIT 5`,
            [userId]
        );
        
        // Calculate security score
        let securityScore = 100;
        if (vulnStats && vulnStats.total > 0) {
            const criticalWeight = (vulnStats.critical || 0) * 20;
            const highWeight = (vulnStats.high || 0) * 10;
            const mediumWeight = (vulnStats.medium || 0) * 5;
            const totalWeight = criticalWeight + highWeight + mediumWeight;
            const maxWeight = (vulnStats.total || 1) * 20;
            securityScore = Math.max(0, Math.min(100, Math.floor(100 - (totalWeight / maxWeight) * 100)));
        }
        
        // Send response
        res.json({
            success: true,
            securityScore: securityScore,
            totalVulnerabilities: vulnStats?.total || 0,
            criticalIssues: vulnStats?.critical || 0,
            highIssues: vulnStats?.high || 0,
            mediumIssues: vulnStats?.medium || 0,
            lowIssues: vulnStats?.low || 0,
            totalScans: scansCount?.total || 0,
            recentScans: recentScans.map(scan => ({
                id: scan.id,
                targetUrl: scan.target_url,
                scanType: scan.scan_type,
                startedAt: scan.started_at,
                duration: scan.duration_seconds,
                status: scan.status,
                securityScore: scan.security_score
            }))
        });
        
    } catch (err) {
        console.error('❌ Dashboard stats error:', err);
        res.status(500).json({ error: 'Failed to load stats: ' + err.message });
    }
});

// Get vulnerability trends for charts
router.get('/trends', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const weeklyData = await allQuery(
            `SELECT 
                strftime('%w', v.created_at) as day_of_week,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium
             FROM vulnerabilities v
             JOIN scans s ON v.scan_id = s.id
             WHERE s.user_id = ? 
                AND v.created_at >= date('now', '-7 days')
             GROUP BY day_of_week
             ORDER BY day_of_week`,
            [userId]
        );
        
        // Default data
        const defaultData = {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            critical: [0, 0, 0, 0, 0, 0, 0],
            high: [0, 0, 0, 0, 0, 0, 0],
            medium: [0, 0, 0, 0, 0, 0, 0]
        };
        
        if (!weeklyData || weeklyData.length === 0) {
            return res.json(defaultData);
        }
        
        // Map SQL day numbers (0=Sun, 1=Mon...6=Sat)
        const dayMap = { 1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5, 0: 6 };
        
        weeklyData.forEach(day => {
            const index = dayMap[day.day_of_week];
            if (index !== undefined) {
                defaultData.critical[index] = day.critical || 0;
                defaultData.high[index] = day.high || 0;
                defaultData.medium[index] = day.medium || 0;
            }
        });
        
        res.json(defaultData);
        
    } catch (err) {
        console.error('❌ Trends error:', err);
        res.status(500).json({ error: 'Failed to load trends' });
    }
});

module.exports = router;
