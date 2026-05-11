const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, '../rakshak.db');
let db;

function initDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) reject(err);
      else {
        console.log('SQLite database connected');
        createTables().then(resolve).catch(reject);
      }
    });
  });
}

function createTables() {
  const queries = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      company TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      target_url TEXT NOT NULL,
      scan_type TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      progress INTEGER DEFAULT 0,
      started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      duration_seconds INTEGER,
      security_score INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`,
    `CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT CHECK(severity IN ('critical','high','medium','low')) NOT NULL,
      location TEXT,
      remediation TEXT,
      status TEXT DEFAULT 'open',
      assigned_to TEXT,
      due_date DATE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(scan_id) REFERENCES scans(id)
    )`,
    `CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      report_type TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT,
      generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`
  ];

  return new Promise((resolve, reject) => {
    let completed = 0;
    queries.forEach(query => {
      db.run(query, (err) => {
        if (err) reject(err);
        completed++;
        if (completed === queries.length) {
          // Add indexes for faster queries
          db.run(`CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)`);
          db.run(`CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)`);
          db.run(`CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)`);
          resolve();
        }
      });
    });
  });
}

function getDb() {
  return db;
}

module.exports = { initDatabase, getDb };
