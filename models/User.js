const { getQuery, runQuery } = require('../config/database');
const bcrypt = require('bcrypt');

async function createUser({ email, password, firstName, lastName, company }) {
    const hashed = await bcrypt.hash(password, 10);
    return runQuery(
        `INSERT INTO users (email, password, first_name, last_name, company) VALUES (?, ?, ?, ?, ?)`,
        [email.toLowerCase(), hashed, firstName, lastName, company || null]
    );
}

async function findUserByEmail(email) {
    return getQuery(`SELECT * FROM users WHERE email = ?`, [email.toLowerCase()]);
}

async function findUserById(id) {
    return getQuery(
        `SELECT id, email, first_name, last_name, company, created_at FROM users WHERE id = ?`,
        [id]
    );
}

async function updateUser(id, updates) {
    const fields = [];
    const values = [];
    
    if (updates.firstName) {
        fields.push('first_name = ?');
        values.push(updates.firstName);
    }
    if (updates.lastName) {
        fields.push('last_name = ?');
        values.push(updates.lastName);
    }
    if (updates.company) {
        fields.push('company = ?');
        values.push(updates.company);
    }
    
    if (fields.length === 0) return null;
    
    values.push(id);
    return runQuery(
        `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
        values
    );
}

module.exports = { createUser, findUserByEmail, findUserById, updateUser };
