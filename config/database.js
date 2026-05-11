const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Railway ke liye persistent path
let DB_PATH;
if (process.env.RAILWAY_VOLUME_MOUNT_PATH) {
    DB_PATH = path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'rakshak.db');
} else if (process.env.NODE_ENV === 'production') {
    DB_PATH = '/tmp/rakshak.db';
} else {
    DB_PATH = path.join(__dirname, '../rakshak.db');
}

console.log('📁 Database path:', DB_PATH);

let db = null;

function initDatabase() {
    return new Promise((resolve, reject) => {
        const dbDir = path.dirname(DB_PATH);
        if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true });
            console.log('📁 Created directory:', dbDir);
        }
        
        db = new sqlite3.Database(DB_PATH, (err) => {
            if (err) {
                console.error('❌ Database connection error:', err);
                reject(err);
                return;
            }
            console.log('✅ SQLite database connected at:', DB_PATH);
            
            db.serialize(() => {
                // Users table
                db.run(`CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    company TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`, (err) => {
                    if (err) console.error('Users table error:', err);
                    else console.log('✅ Users table ready');
                });
                
                // Scans table
                db.run(`CREATE TABLE IF NOT EXISTS scans (
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
                )`, (err) => {
                    if (err) console.error('Scans table error:', err);
                    else console.log('✅ Scans table ready');
                });
                
                // Vulnerabilities table
                db.run(`CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT CHECK(severity IN ('critical','high','medium','low')),
                    location TEXT,
                    remediation TEXT,
                    status TEXT DEFAULT 'open',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )`, (err) => {
                    if (err) console.error('Vulnerabilities table error:', err);
                    else console.log('✅ Vulnerabilities table ready');
                });
                
                // Reports table
                db.run(`CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    report_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT,
                    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )`, (err) => {
                    if (err) console.error('Reports table error:', err);
                    else console.log('✅ Reports table ready');
                });
                
                // Indexes
                db.run(`CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)`);
                db.run(`CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)`);
                db.run(`CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)`);
                
                console.log('✅ All tables and indexes created');
                resolve();
            });
        });
    });
}

function getDb() { return db; }

function getQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('Database not initialized'));
            return;
        }
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function allQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('Database not initialized'));
            return;
        }
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function runQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('Database not initialized'));
            return;
        }
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function closeDatabase() { 
    if (db) db.close(); 
}

module.exports = { 
    initDatabase, 
    getDb, 
    getQuery, 
    allQuery, 
    runQuery, 
    closeDatabase 
};
