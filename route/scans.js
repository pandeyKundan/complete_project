const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/auth');
const { createScan, getScanById, getScansByUser } = require('../models/Scan');
const { simulateScan } = require('../utils/scanSimulator');
const { getVulnerabilitiesByUser } = require('../models/Vulnerability');

router.post('/', isAuthenticated, async (req, res) => {
  try {
    const { targetUrl, scanType } = req.body;
    if (!targetUrl || !scanType) {
      return res.status(400).json({ error: 'Target URL and scan type required' });
    }
    const scan = await createScan(req.session.userId, targetUrl, scanType);
    // Start background simulation
    simulateScan(scan.id, targetUrl, scanType).catch(console.error);
    res.json({ scanId: scan.id, message: 'Scan started' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id', isAuthenticated, async (req, res) => {
  try {
    const scan = await getScanById(req.params.id, req.session.userId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    const allVulns = await getVulnerabilitiesByUser(req.session.userId, {});
    const scanVulns = allVulns.filter(v => v.scan_id === scan.id);
    res.json({ ...scan, vulnerabilities: scanVulns });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/', isAuthenticated, async (req, res) => {
  try {
    const scans = await getScansByUser(req.session.userId, 50);
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
