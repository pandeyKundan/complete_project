const { getDb, getQuery, runQuery } = require('../config/database');
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

module.exports = { createUser, findUserByEmail, findUserById };
