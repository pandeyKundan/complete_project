async function isAuthenticated(req, res, next) {
    // Check if user is logged in via session
    if (req.session && req.session.userId) {
        return next();
    }
    
    // Also check for API key in headers (optional)
    const apiKey = req.headers['x-api-key'];
    if (apiKey && apiKey === process.env.API_KEY) {
        return next();
    }
    
    return res.status(401).json({ error: 'Unauthorized: Please login first' });
}

// Optional: Check if user is admin
async function isAdmin(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { getQuery } = require('../config/database');
    const user = await getQuery('SELECT role FROM users WHERE id = ?', [req.session.userId]);
    
    if (user && user.role === 'admin') {
        return next();
    }
    
    return res.status(403).json({ error: 'Forbidden: Admin access required' });
}

module.exports = { isAuthenticated, isAdmin };
