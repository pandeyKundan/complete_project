const { getDb, getQuery, allQuery, runQuery } = require('../config/database');

async function createScan(userId, targetUrl, scanType) {
  return runQuery(
    `INSERT INTO scans (user_id, target_url, scan_type, status, progress) VALUES (?, ?, ?, 'pending', 0)`,
    [userId, targetUrl, scanType]
  );
}

async function updateScanProgress(scanId, progress, status = null) {
  let sql = `UPDATE scans SET progress = ?`;
  const params = [progress];
  
  if (status) {
    sql += `, status = ?`;
    params.push(status);
    if (status === 'completed') {
      sql += `, completed_at = CURRENT_TIMESTAMP`;
    }
  }
  sql += ` WHERE id = ?`;
  params.push(scanId);
  
  return runQuery(sql, params);
}

async function getScanById(scanId, userId) {
  return getQuery(`SELECT * FROM scans WHERE id = ? AND user_id = ?`, [scanId, userId]);
}

async function getScansByUser(userId, limit = 10) {
  return allQuery(
    `SELECT * FROM scans WHERE user_id = ? ORDER BY started_at DESC LIMIT ?`,
    [userId, limit]
  );
}

async function completeScan(scanId, securityScore, durationSeconds) {
  return runQuery(
    `UPDATE scans SET status = 'completed', security_score = ?, duration_seconds = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [securityScore, durationSeconds, scanId]
  );
}

// Add this for dashboard stats
async function getRecentScans(userId, limit = 5) {
  return allQuery(
    `SELECT id, target_url, scan_type, status, security_score, started_at, completed_at 
     FROM scans WHERE user_id = ? ORDER BY started_at DESC LIMIT ?`,
    [userId, limit]
  );
}

module.exports = { 
  createScan, 
  updateScanProgress, 
  getScanById, 
  getScansByUser, 
  completeScan,
  getRecentScans
};
