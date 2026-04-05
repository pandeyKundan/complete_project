const { getDb } = require('../config/database');

async function createReport(userId, reportType, title, content) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO reports (user_id, report_type, title, content) VALUES (?, ?, ?, ?)`,
      [userId, reportType, title, JSON.stringify(content)],
      function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID });
      }
    );
  });
}

async function getReportsByUser(userId) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT id, report_type, title, generated_at FROM reports WHERE user_id = ? ORDER BY generated_at DESC`,
      [userId],
      (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      }
    );
  });
}

async function getReportById(id, userId) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT * FROM reports WHERE id = ? AND user_id = ?`,
      [id, userId],
      (err, row) => {
        if (err) reject(err);
        else {
          if (row && row.content) row.content = JSON.parse(row.content);
          resolve(row);
        }
      }
    );
  });
}

module.exports = { createReport, getReportsByUser, getReportById };
