require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const cors = require('cors');
const { initDatabase } = require('./config/database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'rakshak_secret_key_change_this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
    },
    name: 'rakshak_session'
}));

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use(express.static(path.join(__dirname, 'public')));

const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');

app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/reports', reportRoutes);

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
    });
}).catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});
