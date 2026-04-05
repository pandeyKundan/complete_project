const { getDb } = require('../config/database');
const bcrypt = require('bcrypt');

async function createUser({ email, password, firstName, lastName, company }) {
  const db = getDb();
  const hashed = await bcrypt.hash(password, 10);
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users (email, password, first_name, last_name, company) VALUES (?, ?, ?, ?, ?)`,
      [email, hashed, firstName, lastName, company],
      function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID, email, firstName, lastName });
      }
    );
  });
}

async function findUserByEmail(email) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

async function findUserById(id) {
  const db = getDb();
  return new Promise((resolve, reject) => {
    db.get(`SELECT id, email, first_name, last_name, company, created_at FROM users WHERE id = ?`, [id], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

module.exports = { createUser, findUserByEmail, findUserById };