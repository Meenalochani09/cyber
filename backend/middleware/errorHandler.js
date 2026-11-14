'use strict';
class HttpError extends Error { constructor(status, message, details) { super(message); this.status = status; this.details = details; } }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === 'string' && UUID.test(v);
const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function notFound(req, res) { res.status(404).json({ ok: false, error: 'Route not found' }); }

function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  if (err.name === 'MulterError') {
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File is too large (max 5 MB).' : 'Upload rejected: ' + err.message;
    return res.status(400).json({ ok: false, error: msg });
  }
  if (err.status) return res.status(err.status).json({ ok: false, error: err.message, details: err.details });
  if (err.type === 'entity.too.large') return res.status(413).json({ ok: false, error: 'Request is too large.' });
  const dbDown = ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET', '57P01', '08006', '08001'].includes(err.code) || /timeout|terminated/i.test(err.message || '');
  console.error('Unhandled error:', err.code || '', err.message); // message only, no request bodies (privacy)
  if (dbDown) return res.status(503).json({ ok: false, error: 'Database unavailable. Check that the Aiven service is running.', code: 'DB_UNAVAILABLE' });
  res.status(500).json({ ok: false, error: 'Internal server error' });
}
module.exports = { HttpError, isUuid, asyncH, notFound, errorHandler };
