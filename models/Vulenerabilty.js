const { getDb } = require('../config/database');

async function addVulnerability(vulnData) {
  const db = getDb();
  const { scanId, title, description, severity, location, remediation } = vulnData;
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO vulnerabilities (scan_id, title, description, severity, location, remediation) VALUES (?, ?, ?, ?, ?, ?)`,
      [scanId, title, description, severity, location, remediation],
      function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID });
      }
    );
  });
}

async function getVulnerabilitiesByUser(userId, filters = {}) {
  const db = getDb();
  let sql = `SELECT v.*, s.target_url FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id WHERE s.user_id = ?`;
  const params = [userId];
  if (filters.severity && filters.severity !== 'all') {
    sql += ` AND v.severity = ?`;
    params.push(filters.severity);
  }
  if (filters.status && filters.status !== 'all') {
    sql += ` AND v.status = ?`;
    params.push(filters.status);
  }
  sql += ` ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, v.created_at DESC`;
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

async function getVulnerabilityById(id, userId) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT v.*, s.target_url FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id WHERE v.id = ? AND s.user_id = ?`,
      [id, userId],
      (err, row) => {
        if (err) reject(err);
        else resolve(row);
      }
    );
  });
}

async function updateVulnerabilityStatus(id, status, userId) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE vulnerabilities SET status = ? WHERE id = ? AND EXISTS (SELECT 1 FROM scans WHERE id = scan_id AND user_id = ?)`,
      [status, id, userId],
      function(err) {
        if (err) reject(err);
        else resolve(this.changes > 0);
      }
    );
  });
}

async function getVulnerabilityStats(userId) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?`,
      [userId],
      (err, row) => {
        if (err) reject(err);
        else resolve(row || { total: 0, critical: 0, high: 0, medium: 0, low: 0, open: 0 });
      }
    );
  });
}

// Helper to get stats for a specific scan (used by scanSimulator)
async function getVulnerabilityStatsByScan(scanId) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT 
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
      FROM vulnerabilities WHERE scan_id = ?`,
      [scanId],
      (err, row) => {
        if (err) reject(err);
        else resolve(row || { critical: 0, high: 0, medium: 0, low: 0 });
      }
    );
  });
}

module.exports = {
  addVulnerability,
  getVulnerabilitiesByUser,
  getVulnerabilityById,
  updateVulnerabilityStatus,
  getVulnerabilityStats,
  getVulnerabilityStatsByScan
};
