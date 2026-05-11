const { getDb, getQuery, allQuery, runQuery } = require('../config/database');

async function createReport(userId, reportType, title, content) {
  return runQuery(
    `INSERT INTO reports (user_id, report_type, title, content) VALUES (?, ?, ?, ?)`,
    [userId, reportType, title, JSON.stringify(content)]
  );
}

async function getReportsByUser(userId) {
  const rows = await allQuery(
    `SELECT id, report_type, title, generated_at FROM reports WHERE user_id = ? ORDER BY generated_at DESC`,
    [userId]
  );
  return rows || [];
}

async function getReportById(id, userId) {
  const row = await getQuery(
    `SELECT * FROM reports WHERE id = ? AND user_id = ?`,
    [id, userId]
  );
  if (row && row.content) {
    row.content = JSON.parse(row.content);
  }
  return row;
}

module.exports = { createReport, getReportsByUser, getReportById };
