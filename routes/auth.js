const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { getDb } = require('../config/database');

// REGISTER - Working version
router.post('/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, company } = req.body;
        
        console.log('Register attempt:', { email, firstName, lastName });
        
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const db = getDb();
        
        // Check if user exists
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE email = ?', [email.toLowerCase()], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (existingUser) {
            return res.status(409).json({ error: 'Email already registered' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const result = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO users (email, password, first_name, last_name, company) VALUES (?, ?, ?, ?, ?)',
                [email.toLowerCase(), hashedPassword, firstName, lastName, company || null],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
        
        // Set session
        req.session.userId = result.id;
        
        console.log('User registered successfully:', email);
        
        res.status(201).json({
            success: true,
            user: { id: result.id, email, firstName, lastName }
        });
        
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Registration failed: ' + err.message });
    }
});

// LOGIN - Working version
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('Login attempt:', email);
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const db = getDb();
        
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        req.session.userId = user.id;
        
        console.log('Login successful:', email);
        
        res.json({
            success: true,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name
            }
        });
        
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed: ' + err.message });
    }
});

// GET CURRENT USER
router.get('/me', async (req, res) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const db = getDb();
        
        const user = await new Promise((resolve, reject) => {
            db.get(
                'SELECT id, email, first_name, last_name, company, created_at FROM users WHERE id = ?',
                [req.session.userId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
        
        if (!user) {
            req.session.destroy();
            return res.status(401).json({ error: 'User not found' });
        }
        
        res.json({
            user: {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                company: user.company,
                created_at: user.created_at
            }
        });
        
    } catch (err) {
        console.error('Me error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// LOGOUT
router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true });
    });
});

module.exports = router;
