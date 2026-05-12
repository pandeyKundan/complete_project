const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { getDb, runQuery, getQuery } = require('../config/database');

router.post('/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, company } = req.body;
        
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const db = getDb();
        
        const existingUser = await getQuery('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
        
        if (existingUser) {
            return res.status(409).json({ error: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await runQuery(
            'INSERT INTO users (email, password, first_name, last_name, company) VALUES (?, ?, ?, ?, ?)',
            [email.toLowerCase(), hashedPassword, firstName, lastName, company || null]
        );
        
        req.session.userId = result.lastID;
        
        res.status(201).json({
            success: true,
            user: { id: result.lastID, email, firstName, lastName }
        });
        
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const db = getDb();
        
        const user = await getQuery('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        req.session.userId = user.id;
        
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
        res.status(500).json({ error: 'Login failed' });
    }
});

router.get('/me', async (req, res) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const db = getDb();
        
        const user = await getQuery(
            'SELECT id, email, first_name, last_name, company, created_at FROM users WHERE id = ?',
            [req.session.userId]
        );
        
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

router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true });
    });
});

module.exports = router;
