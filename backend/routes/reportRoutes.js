'use strict';
const router = require('express').Router();
const { asyncH } = require('../middleware/errorHandler');
router.get('/:id/report', asyncH(require('../controllers/reportController').getReport));
module.exports = router;
