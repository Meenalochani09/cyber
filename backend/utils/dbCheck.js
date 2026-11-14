'use strict';
require('dotenv').config();
const { pool } = require('../config/database');
(async () => {
  try {
    const t = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1");
    console.log('Connected. Tables:', t.rows.map((r) => r.tablename).join(', ') || '(none)');
  } catch (e) { console.error('Connection FAILED:', e.code || '', e.message); process.exitCode = 1; }
  finally { await pool.end(); }
})();
