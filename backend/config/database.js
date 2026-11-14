'use strict';
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL is not set. Copy .env.example to .env and fill it in.');
}

// pg treats sslmode=require as strict verification, which fails against Aiven's own CA,
// so the parameter is removed and SSL is configured explicitly instead.
function cleanUrl(url) {
  try { const u = new URL(url); u.searchParams.delete('sslmode'); return u.toString(); } catch { return url; }
}

const ssl = process.env.DATABASE_CA
  ? { ca: process.env.DATABASE_CA.replace(/\\n/g, '\n'), rejectUnauthorized: true }
  : { rejectUnauthorized: false };

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ? cleanUrl(process.env.DATABASE_URL) : undefined,
  ssl,
  max: process.env.VERCEL ? 3 : 8,                       // the free Aiven plan allows about 20 connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 8000,
});
pool.on('error', (err) => console.error('Database pool error:', err.code || err.message));

module.exports = { pool, query: (text, params) => pool.query(text, params) };
