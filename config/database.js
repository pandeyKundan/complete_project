const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '../rakshak.db');
let db = null;

/**
 * Initialize database connection and create tables
 */
function initDatabase() {
    return new Promise((resolve, reject) => {
        console.log('📁 Initializing database at:', DB_PATH);
        
        // Ensure directory exists
        const dbDir = path.dirname(DB_PATH);
        if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true });
        }
        
        db = new sqlite3.Database(DB_PATH, (err) => {
            if (err) {
                console.error('❌ Database connection error:', err.message);
                reject(err);
                return;
            }
            console.log('✅ SQLite database connected successfully');
            
            // Create all tables
            createTables()
                .then(() => {
                    console.log('✅ All tables created/verified');
                    resolve();
                })
                .catch(reject);
        });
    });
}

/**
 * Create all required tables
 */
function createTables() {
    const queries = [
        // Users table
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            company TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // Scans table
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
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Index for scans - for faster queries
        `CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)`,
        `CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)`,
        
        // Vulnerabilities table
        `CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low')) NOT NULL,
            location TEXT,
            remediation TEXT,
            cvss_score REAL DEFAULT 0,
            status TEXT DEFAULT 'open',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )`,
        
        // Index for vulnerabilities
        `CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)`,
        `CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)`,
        `CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status)`,
        
        // Reports table
        `CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            report_type TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        
        // Index for reports
        `CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)`,
        `CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at)`
    ];

    return new Promise((resolve, reject) => {
        let completed = 0;
        const total = queries.length;
        
        queries.forEach((query, index) => {
            db.run(query, (err) => {
                if (err) {
                    console.error(`❌ Error creating table (query ${index + 1}):`, err.message);
                    reject(err);
                    return;
                }
                completed++;
                if (completed === total) {
                    resolve();
                }
            });
        });
    });
}

/**
 * Get database instance
 */
function getDb() {
    if (!db) {
        throw new Error('Database not initialized. Call initDatabase() first.');
    }
    return db;
}

/**
 * Close database connection
 */
function closeDatabase() {
    return new Promise((resolve, reject) => {
        if (db) {
            db.close((err) => {
                if (err) {
                    console.error('❌ Error closing database:', err.message);
                    reject(err);
                } else {
                    console.log('✅ Database connection closed');
                    db = null;
                    resolve();
                }
            });
        } else {
            resolve();
        }
    });
}

/**
 * Run a query with parameters
 */
function runQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) {
                reject(err);
            } else {
                resolve({ lastID: this.lastID, changes: this.changes });
            }
        });
    });
}

/**
 * Get a single row
 */
function getQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
}

/**
 * Get multiple rows
 */
function allQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

module.exports = {
    initDatabase,
    getDb,
    closeDatabase,
    runQuery,
    getQuery,
    allQuery
};
