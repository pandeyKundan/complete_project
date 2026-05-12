const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '../rakshak.db');
let db = null;

function initDatabase() {
    return new Promise((resolve, reject) => {
        console.log('📁 Initializing database at:', DB_PATH);
        
        const dbDir = path.dirname(DB_PATH);
        if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true });
        }
        
        db = new sqlite3.Database(DB_PATH, (err) => {
            if (err) {
                console.error('❌ Database error:', err.message);
                reject(err);
                return;
            }
            console.log('✅ Database connected');
            
            // Create tables sequentially
            db.serialize(() => {
                db.run(`CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    company TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`, (err) => {
                    if (err) console.error('Users table error:', err.message);
                    else console.log('✅ Users table ready');
                });
                
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
                    if (err) console.error('Scans table error:', err.message);
                    else console.log('✅ Scans table ready');
                });
                
                db.run(`CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    location TEXT,
                    remediation TEXT,
                    status TEXT DEFAULT 'open',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )`, (err) => {
                    if (err) console.error('Vulnerabilities table error:', err.message);
                    else console.log('✅ Vulnerabilities table ready');
                });
                
                db.run(`CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    report_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT,
                    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )`, (err) => {
                    if (err) console.error('Reports table error:', err.message);
                    else console.log('✅ Reports table ready');
                });
            });
            
            resolve();
        });
    });
}

function getDb() {
    if (!db) {
        throw new Error('Database not initialized');
    }
    return db;
}

module.exports = { initDatabase, getDb };
