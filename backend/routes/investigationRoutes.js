'use strict';
const router = require('express').Router();
const c = require('../controllers/investigationController');
const { asyncH } = require('../middleware/errorHandler');
router.post('/', asyncH(c.createInvestigation));
router.get('/', asyncH(c.listInvestigations));
router.get('/:id', asyncH(c.getInvestigation));
router.delete('/:id', asyncH(c.deleteInvestigation));
module.exports = router;
