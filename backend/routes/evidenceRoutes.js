'use strict';
const express = require('express');
const c = require('../controllers/investigationController');
const { asyncH } = require('../middleware/errorHandler');
const { upload } = require('../middleware/uploadMiddleware');
const inv = express.Router();     // mounted at /api/investigations
inv.post('/:id/evidence', upload.single('file'), asyncH(c.addEvidence));
inv.get('/:id/evidence', asyncH(c.listEvidence));
const ev = express.Router();      // mounted at /api/evidence
ev.get('/:id', asyncH(c.getEvidence));
ev.patch('/:id', asyncH(c.updateEvidenceText));
ev.get('/:id/file', asyncH(c.getEvidenceFile));
ev.delete('/:id', asyncH(c.deleteEvidence));
module.exports = { investigationScoped: inv, evidenceScoped: ev };
