'use strict';
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { query } = require('./config/database');
const { notFound, errorHandler } = require('./middleware/errorHandler');
const evidenceRoutes = require('./routes/evidenceRoutes');

const app = express();
const origins = (process.env.FRONTEND_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean);
app.disable('x-powered-by');
app.use(cors((req, cb) => {
  const origin = req.header('Origin');
  let sameOrigin = false;
  try { sameOrigin = !!origin && new URL(origin).host === (req.header('x-forwarded-host') || req.header('host')); } catch { /* bad Origin header */ }
  const allowed = !origin || sameOrigin || origins.includes(origin);
  cb(allowed ? null : new Error('Origin not allowed by CORS'), { origin: allowed, methods: ['GET', 'POST', 'PATCH', 'DELETE'] });
}));
app.use(express.json({ limit: '200kb' }));

// Health check: the frontend uses this to decide between REAL and DEMO mode.
app.get('/api/health', async (req, res) => {
  try { await query('SELECT 1'); res.json({ ok: true, status: 'up', database: 'connected', mode: 'real' }); }
  catch { res.status(503).json({ ok: false, status: 'degraded', database: 'unavailable' }); }
});

app.use('/api/investigations', require('./routes/investigationRoutes'));
app.use('/api/investigations', evidenceRoutes.investigationScoped);
app.use('/api/investigations', require('./routes/analysisRoutes'));
app.use('/api/investigations', require('./routes/reportRoutes'));
app.use('/api/evidence', evidenceRoutes.evidenceScoped);
// Serves the frontend from the same server (used on Vercel; harmless locally).
app.use(express.static(require('path').join(__dirname, '..', 'frontend')));
app.use(notFound);
app.use((err, req, res, next) => (err.message === 'Origin not allowed by CORS' ? res.status(403).json({ ok: false, error: err.message }) : errorHandler(err, req, res, next)));

const port = process.env.PORT || 4000;
if (require.main === module) app.listen(port, () => console.log(`TRACELYT backend listening on port ${port}`));
module.exports = app;
