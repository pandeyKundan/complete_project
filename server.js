require('dotenv').config();
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const { initDatabase } = require('./config/database');

// Import routes
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');

const app = express();
const PORT = process.env.PORT || 3000;

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

// Session configuration with file store for persistence
app.use(session({
    store: new FileStore({
        path: './sessions',
        ttl: 86400,  // 24 hours in seconds
        retries: 0
    }),
    secret: process.env.SESSION_SECRET || 'rakshak_secret_key_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    },
    name: 'rakshak.sid'
}));

// ========== HEALTH CHECK ==========
app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// ========== STATIC FILES ==========
app.use(express.static(path.join(__dirname, 'public')));

// ========== API ROUTES ==========
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/reports', reportRoutes);

// ========== SPA CATCH-ALL ==========
app.get('*', (req, res) => {
    // Don't interfere with API routes
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== ERROR HANDLER ==========
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ========== START SERVER ==========
async function startServer() {
    try {
        await initDatabase();
        
        // Ensure sessions directory exists
        if (!fs.existsSync('./sessions')) {
            fs.mkdirSync('./sessions');
            console.log('📁 Sessions directory created');
        }
        
        app.listen(PORT, () => {
            console.log(`🚀 Rakshak backend running on port ${PORT}`);
            console.log(`📍 Health check: http://localhost:${PORT}/api/health`);
            console.log(`📍 Dashboard: http://localhost:${PORT}/dashboard.html`);
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
}

startServer();
