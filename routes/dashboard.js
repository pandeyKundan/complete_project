const express = require('express');
const router = express.Router();
const { getDb, allQuery, getQuery } = require('../config/database');

/**
 * Middleware to check authentication
 */
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

/**
 * @route   GET /api/dashboard/stats
 * @desc    Get dashboard statistics
 * @access  Private
 */
router.get('/stats', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const db = getDb();
        
        // Get vulnerability statistics
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
        
        // Get recent scans
        const recentScans = await allQuery(
            `SELECT id, target_url, scan_type, status, progress, 
                    started_at, completed_at, duration_seconds, security_score
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
            securityScore = Math.max(0, Math.min(100, 100 - (totalWeight / maxWeight) * 100));
        }
        
        res.json({
            securityScore: Math.floor(securityScore),
            totalVulnerabilities: vulnStats?.total || 0,
            criticalIssues: vulnStats?.critical || 0,
            highIssues: vulnStats?.high || 0,
            mediumIssues: vulnStats?.medium || 0,
            lowIssues: vulnStats?.low || 0,
            recentScans: recentScans.map(scan => ({
                id: scan.id,
                targetUrl: scan.target_url,
                scanType: scan.scan_type,
                status: scan.status,
                progress: scan.progress,
                startedAt: scan.started_at,
                completedAt: scan.completed_at,
                duration: scan.duration_seconds,
                securityScore: scan.security_score
            }))
        });
        
    } catch (err) {
        console.error('❌ Dashboard stats error:', err);
        res.status(500).json({ error: 'Failed to load dashboard stats' });
    }
});

/**
 * @route   GET /api/dashboard/trends
 * @desc    Get vulnerability trends over time
 * @access  Private
 */
router.get('/trends', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        // Get weekly vulnerability counts
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
        
        // Default weekly data if no real data exists
        const defaultTrends = {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            critical: [0, 0, 0, 0, 0, 0, 0],
            high: [0, 0, 0, 0, 0, 0, 0],
            medium: [0, 0, 0, 0, 0, 0, 0]
        };
        
        if (weeklyData.length === 0) {
            return res.json(defaultTrends);
        }
        
        // Map SQL day numbers to Monday-Sunday (Sunday = 0 in SQL, we convert)
        const dayMap = { 1: 'Mon', 2: 'Tue', 3: 'Wed', 4: 'Thu', 5: 'Fri', 6: 'Sat', 0: 'Sun' };
        const critical = [0, 0, 0, 0, 0, 0, 0];
        const high = [0, 0, 0, 0, 0, 0, 0];
        const medium = [0, 0, 0, 0, 0, 0, 0];
        
        weeklyData.forEach(day => {
            let index = day.day_of_week;
            if (index === 0) index = 6; // Move Sunday to end
            else index = day.day_of_week - 1;
            critical[index] = day.critical || 0;
            high[index] = day.high || 0;
            medium[index] = day.medium || 0;
        });
        
        res.json({
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            critical,
            high,
            medium
        });
        
    } catch (err) {
        console.error('❌ Trends error:', err);
        res.status(500).json({ error: 'Failed to load trends' });
    }
});

module.exports = router;
