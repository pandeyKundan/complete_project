require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const cors = require('cors');
const { initDatabase } = require('./config/database');
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

// Serve static files from "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/reports', reportRoutes);

// ========== IMPORTANT FIX: Serve index.html for root path ==========
// This sends the HOMEPAGE (landing page) when someone visits /
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Handle 404 for unknown API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// Error handler
app.use(errorHandler);

initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Rakshak backend running on http://localhost:${PORT}`);
    console.log(`📄 Homepage: http://localhost:${PORT}/`);
    console.log(`🔐 Login: http://localhost:${PORT}/login.html`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard.html`);
  });
}).catch(err => {
  console.error('Database init failed:', err);
  process.exit(1);
});
