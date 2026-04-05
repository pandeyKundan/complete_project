const { updateScanProgress, completeScan } = require('../models/Scan');
const { addVulnerability, getVulnerabilityStatsByScan } = require('../models/Vulnerability');

const vulnerabilityTemplates = [
  { title: 'SQL Injection', severity: 'critical', description: 'User input not sanitized in SQL query.', remediation: 'Use parameterized queries or prepared statements.' },
  { title: 'Cross-Site Scripting (XSS)', severity: 'high', description: 'Reflected XSS in search parameter.', remediation: 'Implement output encoding and Content Security Policy.' },
  { title: 'Missing Security Headers', severity: 'medium', description: 'X-Frame-Options header not set.', remediation: 'Add security headers (X-Frame-Options, X-Content-Type-Options, etc.).' },
  { title: 'Information Disclosure', severity: 'low', description: 'Server version exposed in HTTP headers.', remediation: 'Hide server version and disable detailed error messages.' },
  { title: 'CSRF Vulnerability', severity: 'medium', description: 'No CSRF tokens used in state-changing operations.', remediation: 'Implement anti-CSRF tokens or SameSite cookies.' },
  { title: 'Weak Password Policy', severity: 'high', description: 'No password complexity requirements.', remediation: 'Enforce strong password policies.' },
  { title: 'Directory Listing Enabled', severity: 'medium', description: 'Sensitive directories are browsable.', remediation: 'Disable directory listing in web server configuration.' }
];

async function simulateScan(scanId, targetUrl, scanType) {
  const totalSteps = scanType === 'quick' ? 20 : 50;
  const maxVulns = scanType === 'quick' ? 5 : 12;

  for (let step = 1; step <= totalSteps; step++) {
    const progress = Math.floor((step / totalSteps) * 100);
    await updateScanProgress(scanId, progress);

    // Randomly add a vulnerability at certain steps
    if (Math.random() < 0.15 && step % 3 === 0) {
      const template = vulnerabilityTemplates[Math.floor(Math.random() * vulnerabilityTemplates.length)];
      // Check if we haven't exceeded max vulnerabilities
      const stats = await getVulnerabilityStatsByScan(scanId);
      const currentCount = (stats.critical + stats.high + stats.medium + stats.low) || 0;
      if (currentCount < maxVulns) {
        await addVulnerability({
          scanId,
          title: template.title,
          description: template.description,
          severity: template.severity,
          location: `${targetUrl}/some/path?param=test`,
          remediation: template.remediation
        });
      }
    }

    // Simulate time delay
    await new Promise(resolve => setTimeout(resolve, scanType === 'quick' ? 150 : 300));
  }

  // After scan completes, compute security score based on found vulnerabilities
  const stats = await getVulnerabilityStatsByScan(scanId);
  const totalVulns = (stats.critical || 0) + (stats.high || 0) + (stats.medium || 0) + (stats.low || 0);
  let score = 100 - (stats.critical * 20 + stats.high * 10 + stats.medium * 5 + stats.low * 2);
  score = Math.max(0, Math.min(100, score));

  const durationSeconds = scanType === 'quick' ? totalSteps * 0.15 : totalSteps * 0.3;
  await completeScan(scanId, Math.floor(score), Math.floor(durationSeconds));
  await updateScanProgress(scanId, 100, 'completed');
}

module.exports = { simulateScan };