const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { getDb, runQuery, getQuery } = require('../config/database');

const SALT_ROUNDS = 10;

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, company } = req.body;
        
        // Validation
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['email', 'password', 'firstName', 'lastName']
            });
        }
        
        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Password strength validation
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        const db = getDb();
        
        // Check if user already exists
        const existingUser = await getQuery(
            'SELECT id FROM users WHERE email = ?',
            [email.toLowerCase()]
        );
        
        if (existingUser) {
            return res.status(409).json({ error: 'Email already registered' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
        // Create user
        const result = await runQuery(
            `INSERT INTO users (email, password, first_name, last_name, company) 
             VALUES (?, ?, ?, ?, ?)`,
            [email.toLowerCase(), hashedPassword, firstName, lastName, company || null]
        );
        
        // Set session
        req.session.userId = result.lastID;
        
        // Return user info (excluding password)
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: {
                id: result.lastID,
                email: email.toLowerCase(),
                firstName,
                lastName,
                company: company || null
            }
        });
        
    } catch (err) {
        console.error('❌ Registration error:', err);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const db = getDb();
        
        // Find user by email
        const user = await getQuery(
            'SELECT * FROM users WHERE email = ?',
            [email.toLowerCase()]
        );
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Set session
        req.session.userId = user.id;
        
        // Update last login time (optional - add column if needed)
        // await runQuery('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
        
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                company: user.company,
                createdAt: user.created_at
            }
        });
        
    } catch (err) {
        console.error('❌ Login error:', err);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

/**
 * @route   GET /api/auth/me
 * @desc    Get current authenticated user
 * @access  Private
 */
router.get('/me', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const user = await getQuery(
            `SELECT id, email, first_name, last_name, company, created_at 
             FROM users WHERE id = ?`,
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
        console.error('❌ Me endpoint error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

/**
 * @route   POST /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post('/change-password', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current password and new password required' });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters' });
        }
        
        const user = await getQuery(
            'SELECT password FROM users WHERE id = ?',
            [req.session.userId]
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const isValid = await bcrypt.compare(currentPassword, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        
        await runQuery(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, req.session.userId]
        );
        
        res.json({ success: true, message: 'Password changed successfully' });
        
    } catch (err) {
        console.error('❌ Change password error:', err);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

module.exports = router;
