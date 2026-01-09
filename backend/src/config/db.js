const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// เทสการเชื่อมต่อ
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error(' Database Connection Failed:', err.message);
  } else {
    console.log(' Database Connected Successfully!');
  }
});

module.exports = pool;