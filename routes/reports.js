const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/auth');
const { createReport, getReportsByUser, getReportById } = require('../models/Report');
const { getScansByUser } = require('../models/Scan');
const { getVulnerabilitiesByUser } = require('../models/Vulnerability');

// Generate a new report
router.post('/generate', isAuthenticated, async (req, res) => {
  try {
    const { scanId, reportType, title } = req.body;
    
    if (!scanId || !reportType || !title) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const scans = await getScansByUser(req.session.userId, 100);
    const scan = scans.find(s => s.id == scanId);
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    const vulns = await getVulnerabilitiesByUser(req.session.userId, {});
    const scanVulns = vulns.filter(v => v.scan_id == scanId);
    
    const reportContent = {
      scan: {
        targetUrl: scan.target_url,
        scanType: scan.scan_type,
        startedAt: scan.started_at,
        completedAt: scan.completed_at,
        durationSeconds: scan.duration_seconds,
        securityScore: scan.security_score || 85
      },
      vulnerabilities: scanVulns.map(v => ({
        id: v.id,
        title: v.title,
        description: v.description,
        severity: v.severity,
        location: v.location,
        remediation: v.remediation,
        created_at: v.created_at
      })),
      summary: {
        total: scanVulns.length,
        critical: scanVulns.filter(v => v.severity === 'critical').length,
        high: scanVulns.filter(v => v.severity === 'high').length,
        medium: scanVulns.filter(v => v.severity === 'medium').length,
        low: scanVulns.filter(v => v.severity === 'low').length
      }
    };
    
    const report = await createReport(req.session.userId, reportType, title, reportContent);
    res.json({ reportId: report.lastID, success: true });
    
  } catch (err) {
    console.error('Report generation error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get all reports for user
router.get('/', isAuthenticated, async (req, res) => {
  try {
    const reports = await getReportsByUser(req.session.userId);
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get specific report
router.get('/:id', isAuthenticated, async (req, res) => {
  try {
    const report = await getReportById(req.params.id, req.session.userId);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
