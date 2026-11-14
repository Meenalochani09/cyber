'use strict';
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const os = require('os');
// Vercel's filesystem is read-only except /tmp, which is temporary. Screenshots uploaded there do not persist.
const dir = process.env.VERCEL ? path.join(os.tmpdir(), 'uploads') : path.join(__dirname, '..', 'uploads');
fs.mkdirSync(dir, { recursive: true });
const ALLOWED = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp' };

const storage = multer.diskStorage({
  destination: dir,
  // Random name; the original filename is never used for the path (prevents traversal).
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + (ALLOWED[file.mimetype] || '')),
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED[file.mimetype]) return cb(Object.assign(new Error('Only PNG, JPG or WEBP images are allowed.'), { status: 400 }));
    cb(null, true);
  },
});

// Checks the real file signature, not just the declared type.
function verifyImageSignature(filePath) {
  const b = Buffer.alloc(12); const fd = fs.openSync(filePath, 'r'); fs.readSync(fd, b, 0, 12, 0); fs.closeSync(fd);
  const png = b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const jpg = b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  const webp = b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP';
  return png || jpg || webp;
}
module.exports = { upload, verifyImageSignature, uploadDir: dir };
