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

// ========== SESSION DIRECTORY FOR RENDER ==========
const sessionDir = process.env.NODE_ENV === 'production' ? '/tmp/sessions' : './sessions';
if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
    console.log(`📁 Session directory created: ${sessionDir}`);
}

// ========== CORS CONFIGURATION ==========
const allowedOrigins = ['https://complete-project-5slz.onrender.com', 'http://localhost:3000', 'http://localhost:5000'];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            console.log(`CORS blocked origin: ${origin}`);
            return callback(new Error('CORS not allowed'), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie']
}));

// Handle preflight requests
app.options('*', cors());

// ========== SESSION CONFIGURATION ==========
app.use(session({
    store: new FileStore({
        path: sessionDir,
        ttl: 86400,  // 24 hours in seconds
        retries: 0
    }),
    secret: process.env.SESSION_SECRET || 'rakshak_production_secret_key_2025_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,           // Important: false for Render (HTTPS is handled by proxy)
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,  // 24 hours
        domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined
    },
    name: 'rakshak.sid'
}));

// ========== COOKIE HELPER MIDDLEWARE ==========
app.use((req, res, next) => {
    // Ensure CORS headers for every response
    res.header('Access-Control-Allow-Credentials', 'true');
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    
    // Log session for debugging (remove in production)
    if (req.session && req.session.userId) {
        console.log(`Session active for user: ${req.session.userId}`);
    }
    next();
});

// ========== HEALTH CHECK ==========
app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// ========== TEST DATABASE ENDPOINT (Remove after testing) ==========
app.get('/api/test-db', async (req, res) => {
    try {
        const { getQuery } = require('./config/database');
        const result = await getQuery('SELECT 1 as test');
        res.json({ success: true, message: 'Database works!', result });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ========== STATIC FILES ==========
app.use(express.static(path.join(__dirname, 'public')));

// ========== API ROUTES ==========
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/reports', reportRoutes);

// ========== SPA CATCH-ALL ROUTE ==========
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
        console.log('✅ Database initialized successfully');
        
        app.listen(PORT, () => {
            console.log(`🚀 Rakshak backend running on port ${PORT}`);
            console.log(`📍 Health check: http://localhost:${PORT}/api/health`);
            console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`📍 Session directory: ${sessionDir}`);
        });
    } catch (err) {
        console.error('❌ Failed to start server:', err);
        process.exit(1);
    }
}

startServer();
