const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/auth');
const { getVulnerabilitiesByUser, getVulnerabilityById, updateVulnerabilityStatus } = require('../models/Vulnerability');

router.get('/', isAuthenticated, async (req, res) => {
  try {
    const { severity, status } = req.query;
    const filters = { severity: severity || 'all', status: status || 'all' };
    const vulns = await getVulnerabilitiesByUser(req.session.userId, filters);
    res.json(vulns);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id', isAuthenticated, async (req, res) => {
  try {
    const vuln = await getVulnerabilityById(req.params.id, req.session.userId);
    if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });
    res.json(vuln);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/:id/status', isAuthenticated, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['open', 'fixed', 'false_positive'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    const updated = await updateVulnerabilityStatus(req.params.id, status, req.session.userId);
    if (!updated) return res.status(404).json({ error: 'Vulnerability not found or not owned' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;  // <-- MUST export router
