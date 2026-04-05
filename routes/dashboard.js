const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/auth');
const { getVulnerabilityStats } = require('../models/Vulnerability');
const { getScansByUser } = require('../models/Scan');

router.get('/stats', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const vulnStats = await getVulnerabilityStats(userId);
    const recentScans = await getScansByUser(userId, 5);

    let totalWeight = (vulnStats.critical || 0) * 20 +
                      (vulnStats.high || 0) * 10 +
                      (vulnStats.medium || 0) * 5 +
                      (vulnStats.low || 0) * 2;
    let maxWeight = (vulnStats.total || 1) * 20;
    let securityScore = Math.floor(100 - (totalWeight / maxWeight) * 100);
    securityScore = Math.max(0, Math.min(100, securityScore));

    res.json({
      securityScore,
      totalVulnerabilities: vulnStats.total || 0,
      criticalIssues: vulnStats.critical || 0,
      recentScans: recentScans.map(s => ({
        targetUrl: s.target_url,
        startedAt: s.started_at,
        duration: s.duration_seconds,
        status: s.status
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/trends', isAuthenticated, (req, res) => {
  // For demo purposes, return fixed trend data.
  // In a real app, you would compute this from your database.
  res.json({
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    critical: [2, 3, 1, 4, 3, 2, 3],
    high: [5, 7, 6, 8, 7, 6, 5],
    medium: [12, 10, 14, 15, 13, 11, 12]
  });
});

module.exports = router;