const { Pool } = require('pg');
const pool = new Pool({
  user:     'postgres',
  host:     'localhost',
  database: 'exam',   // ← менять
  password: 'qwerty666',    // ← менять
  port:     5432,
});
module.exports = pool;