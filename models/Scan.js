const { getDb } = require('../config/database');

async function createScan(userId, targetUrl, scanType) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO scans (user_id, target_url, scan_type, status, progress) VALUES (?, ?, ?, 'pending', 0)`,
      [userId, targetUrl, scanType],
      function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID });
      }
    );
  });
}

async function updateScanProgress(scanId, progress, status = null) {
  const db = getDb();
  let sql = `UPDATE scans SET progress = ?`;
  const params = [progress];
  if (status) {
    sql += `, status = ?`;
    params.push(status);
    if (status === 'completed') sql += `, completed_at = CURRENT_TIMESTAMP`;
  }
  sql += ` WHERE id = ?`;
  params.push(scanId);
  return new Promise((resolve, reject) => {
    db.run(sql, params, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function getScanById(scanId, userId) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM scans WHERE id = ? AND user_id = ?`, [scanId, userId], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

async function getScansByUser(userId, limit = 10) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.all(`SELECT * FROM scans WHERE user_id = ? ORDER BY started_at DESC LIMIT ?`, [userId, limit], (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

async function completeScan(scanId, securityScore, durationSeconds) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE scans SET status = 'completed', security_score = ?, duration_seconds = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [securityScore, durationSeconds, scanId],
      (err) => {
        if (err) reject(err);
        else resolve();
      }
    );
  });
}

module.exports = { createScan, updateScanProgress, getScanById, getScansByUser, completeScan };
