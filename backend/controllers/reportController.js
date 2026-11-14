'use strict';
const { query } = require('../config/database');
const { getInvestigationOr404, loadCase } = require('./investigationController');
const { analyse } = require('../services/riskAnalyzer');
const { buildReportData, toPdf } = require('../services/reportGenerator');

exports.getReport = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { evidence, entities } = await loadCase(inv.id);
  const relationships = (await query('SELECT * FROM relationships WHERE investigation_id=$1', [inv.id])).rows;
  const events = (await query('SELECT * FROM investigation_events WHERE investigation_id=$1 ORDER BY timestamp_known DESC, event_timestamp ASC', [inv.id])).rows;
  const report = buildReportData({ investigation: inv, evidence, entities, relationships, events, risk: analyse(evidence, entities) });
  if (req.query.format === 'pdf') {
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="tracelyt-report-${inv.id.slice(0, 8)}.pdf"`);
    return toPdf(report, res);
  }
  res.json({ ok: true, mode: 'real', data: report });
};
