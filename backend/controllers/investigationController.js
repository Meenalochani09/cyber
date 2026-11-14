'use strict';
const fs = require('fs');
const path = require('path');
const { pool, query } = require('../config/database');
const { HttpError, isUuid } = require('../middleware/errorHandler');
const { verifyImageSignature, uploadDir } = require('../middleware/uploadMiddleware');
const { extractFromEvidence, parseTimestamp } = require('../services/evidenceExtractor');
const { analyse } = require('../services/riskAnalyzer');
const { buildRelationships, buildTimeline } = require('../services/relationshipBuilder');

const EVIDENCE_TYPES = ['sms', 'whatsapp', 'url', 'upi', 'screenshot', 'note'];
const MAX_TEXT = 20000;

const needId = (v, label = 'id') => { if (!isUuid(v)) throw new HttpError(400, `Invalid ${label}.`); return v; };
const clean = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

async function getInvestigationOr404(id) {
  const { rows } = await query('SELECT * FROM investigations WHERE id = $1', [needId(id)]);
  if (!rows[0]) throw new HttpError(404, 'Investigation not found.');
  return rows[0];
}

// ---------- Investigations ----------
exports.createInvestigation = async (req, res) => {
  const name = clean(req.body.case_name, 200);
  if (!name) throw new HttpError(400, 'case_name is required.');
  const { rows } = await query(
    `INSERT INTO investigations (case_name, case_description, scam_category, analysis_mode)
     VALUES ($1,$2,$3,'real') RETURNING *`,
    [name, clean(req.body.case_description, 5000) || null, clean(req.body.scam_category, 100) || null]);
  res.status(201).json({ ok: true, mode: 'real', data: rows[0] });
};

exports.listInvestigations = async (req, res) => {
  const { rows } = await query(
    `SELECT i.*, (SELECT count(*) FROM evidence e WHERE e.investigation_id = i.id)::int AS evidence_count,
            (SELECT count(*) FROM relationships r WHERE r.investigation_id = i.id)::int AS relationship_count
     FROM investigations i ORDER BY i.created_at DESC LIMIT 200`);
  const stats = {
    investigations: rows.length,
    evidence: rows.reduce((a, r) => a + r.evidence_count, 0),
    relationships: rows.reduce((a, r) => a + r.relationship_count, 0),
    high_concern: rows.filter((r) => r.risk_level === 'high_concern').length,
  };
  res.json({ ok: true, mode: 'real', data: rows, stats });
};

exports.getInvestigation = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  res.json({ ok: true, mode: 'real', data: inv });
};

exports.deleteInvestigation = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { rows } = await query('SELECT storage_reference FROM evidence WHERE investigation_id=$1 AND storage_reference IS NOT NULL', [inv.id]);
  await query('DELETE FROM investigations WHERE id = $1', [inv.id]);
  rows.forEach((r) => removeFile(r.storage_reference));
  res.json({ ok: true, data: { deleted: inv.id } });
};

function removeFile(ref) {
  try { fs.unlinkSync(path.join(uploadDir, path.basename(ref))); } catch { /* already gone */ }
}

// ---------- Evidence ----------
exports.addEvidence = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const type = clean(req.body.evidence_type, 20).toLowerCase();
  if (!EVIDENCE_TYPES.includes(type)) { if (req.file) removeFile(req.file.filename); throw new HttpError(400, 'evidence_type must be one of: ' + EVIDENCE_TYPES.join(', ')); }

  let text = clean(req.body.original_text, MAX_TEXT) || null;
  let storageRef = null; let status = 'pending';

  if (req.file) {
    if (type !== 'screenshot') { removeFile(req.file.filename); throw new HttpError(400, 'Files can only be attached to screenshot evidence.'); }
    if (!verifyImageSignature(req.file.path)) { removeFile(req.file.filename); throw new HttpError(400, 'The file is not a valid image.'); }
    storageRef = req.file.filename;
    // OCR is not installed in this build. Text must be typed in, and the status says so honestly.
    if (!text) status = 'manual_entry_required';
  } else if (type === 'screenshot') {
    throw new HttpError(400, 'Attach an image file for screenshot evidence.');
  }
  if (!text && !storageRef) throw new HttpError(400, 'original_text is required.');

  let ts = null;
  if (req.body.incident_timestamp) {
    ts = parseTimestamp(req.body.incident_timestamp);
    if (!ts) { if (req.file) removeFile(req.file.filename); throw new HttpError(400, 'incident_timestamp is not a valid date/time.'); }
  }
  const { rows } = await query(
    `INSERT INTO evidence (investigation_id, evidence_type, original_text, storage_reference, source_identifier, incident_timestamp, processing_status)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [inv.id, type, text, storageRef, clean(req.body.source_identifier, 200) || null, ts, status]);
  res.status(201).json({ ok: true, mode: 'real', data: rows[0],
    notice: status === 'manual_entry_required' ? 'Text could not be extracted from the image automatically. Please type the visible text into the evidence so it can be analysed.' : undefined });
};

exports.updateEvidenceText = async (req, res) => {
  const text = clean(req.body.original_text, MAX_TEXT);
  if (!text) throw new HttpError(400, 'original_text is required.');
  const { rows } = await query(
    `UPDATE evidence SET original_text=$2, processing_status='pending' WHERE id=$1 RETURNING *`, [needId(req.params.id), text]);
  if (!rows[0]) throw new HttpError(404, 'Evidence not found.');
  res.json({ ok: true, data: rows[0] });
};

exports.listEvidence = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const params = [inv.id]; let where = 'investigation_id = $1';
  if (req.query.type) { params.push(String(req.query.type)); where += ` AND evidence_type = $${params.length}`; }
  if (req.query.q) { params.push('%' + String(req.query.q).slice(0, 100) + '%'); where += ` AND original_text ILIKE $${params.length}`; }
  const { rows } = await query(`SELECT * FROM evidence WHERE ${where} ORDER BY created_at ASC`, params);
  res.json({ ok: true, mode: 'real', data: rows });
};

exports.getEvidence = async (req, res) => {
  const { rows } = await query('SELECT * FROM evidence WHERE id=$1', [needId(req.params.id)]);
  if (!rows[0]) throw new HttpError(404, 'Evidence not found.');
  const ents = await query('SELECT * FROM extracted_entities WHERE evidence_id=$1 ORDER BY entity_type', [rows[0].id]);
  res.json({ ok: true, data: { ...rows[0], entities: ents.rows } });
};

exports.deleteEvidence = async (req, res) => {
  const { rows } = await query('DELETE FROM evidence WHERE id=$1 RETURNING id, storage_reference', [needId(req.params.id)]);
  if (!rows[0]) throw new HttpError(404, 'Evidence not found.');
  if (rows[0].storage_reference) removeFile(rows[0].storage_reference);
  res.json({ ok: true, data: { deleted: rows[0].id } });
};

exports.getEvidenceFile = async (req, res) => {
  const { rows } = await query('SELECT storage_reference FROM evidence WHERE id=$1', [needId(req.params.id)]);
  if (!rows[0] || !rows[0].storage_reference) throw new HttpError(404, 'No file for this evidence.');
  const file = path.join(uploadDir, path.basename(rows[0].storage_reference));
  if (!fs.existsSync(file)) throw new HttpError(404, 'File no longer exists.');
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.sendFile(file);
};

// ---------- Analysis ----------
async function loadCase(invId) {
  const evidence = (await query('SELECT * FROM evidence WHERE investigation_id=$1 ORDER BY created_at', [invId])).rows;
  const entities = (await query(
    `SELECT x.* FROM extracted_entities x JOIN evidence e ON e.id = x.evidence_id WHERE e.investigation_id=$1`, [invId])).rows;
  return { evidence, entities };
}

exports.analyse = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const evidence = (await query('SELECT * FROM evidence WHERE investigation_id=$1 ORDER BY created_at', [inv.id])).rows;
  if (!evidence.length) throw new HttpError(400, 'Add at least one piece of evidence before running analysis.');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM relationships WHERE investigation_id=$1', [inv.id]);
    await client.query('DELETE FROM investigation_events WHERE investigation_id=$1', [inv.id]);
    await client.query('DELETE FROM extracted_entities WHERE evidence_id = ANY($1::uuid[])', [evidence.map((e) => e.id)]);

    const stored = [];
    for (const ev of evidence) {
      const items = extractFromEvidence(ev);
      for (const it of items) {
        const r = await client.query(
          `INSERT INTO extracted_entities (evidence_id, entity_type, entity_value, normalized_value, extraction_method, confidence, explanation)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
          [it.evidence_id, it.entity_type, it.entity_value, it.normalized_value, it.extraction_method, it.confidence, it.explanation]);
        stored.push(r.rows[0]);
      }
      const hasText = !!(ev.original_text && ev.original_text.trim());
      await client.query('UPDATE evidence SET processing_status=$2 WHERE id=$1', [ev.id, hasText ? 'processed' : 'manual_entry_required']);
    }
    const rels = buildRelationships(inv.id, evidence, stored);
    for (const r of rels) {
      await client.query(
        `INSERT INTO relationships (investigation_id, source_entity_id, target_entity_id, relationship_type, explanation, supporting_evidence_id)
         VALUES ($1,$2,$3,$4,$5,$6)`, [r.investigation_id, r.source_entity_id, r.target_entity_id, r.relationship_type, r.explanation, r.supporting_evidence_id]);
    }
    const events = buildTimeline(inv.id, evidence, stored);
    for (const e of events) {
      await client.query(
        `INSERT INTO investigation_events (investigation_id, evidence_id, event_description, event_timestamp, timestamp_known)
         VALUES ($1,$2,$3,$4,$5)`, [e.investigation_id, e.evidence_id, e.event_description, e.event_timestamp, e.timestamp_known]);
    }
    const risk = analyse(evidence, stored);
    await client.query('UPDATE investigations SET risk_level=$2, updated_at=now() WHERE id=$1', [inv.id, risk.risk_level]);
    await client.query('COMMIT');
    res.json({ ok: true, mode: 'real', label: 'REAL ANALYSIS',
      data: { investigation_id: inv.id, entities: stored.length, relationships: rels.length, events: events.length, risk } });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
};

exports.getEntities = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { entities } = await loadCase(inv.id);
  res.json({ ok: true, mode: 'real', data: entities });
};

exports.getRisk = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { evidence, entities } = await loadCase(inv.id);
  res.json({ ok: true, mode: 'real', data: analyse(evidence, entities) });
};

// Graph payload for Cytoscape. Entities with the same type+value are merged into one node.
exports.getRelationships = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { evidence, entities } = await loadCase(inv.id);
  const rels = (await query('SELECT * FROM relationships WHERE investigation_id=$1', [inv.id])).rows;
  const evById = new Map(evidence.map((e) => [e.id, e]));
  const entById = new Map(entities.map((e) => [e.id, e]));
  const nodeKey = (e) => e.entity_type + '|' + e.normalized_value;

  const nodes = new Map();
  const touch = (e) => {
    const k = nodeKey(e);
    if (!nodes.has(k)) nodes.set(k, { id: k, label: e.entity_value, entity_type: e.entity_type, evidence_ids: new Set(), evidence_types: new Set(), explanations: [] });
    const n = nodes.get(k);
    n.evidence_ids.add(e.evidence_id);
    const ev = evById.get(e.evidence_id); if (ev) n.evidence_types.add(ev.evidence_type);
    if (e.explanation && !n.explanations.includes(e.explanation)) n.explanations.push(e.explanation);
  };
  const edges = [];
  for (const r of rels) {
    const a = entById.get(r.source_entity_id), b = entById.get(r.target_entity_id);
    if (!a || !b) continue;
    touch(a); touch(b);
    const s = nodeKey(a), t = nodeKey(b);
    if (s === t) continue; // same value in two evidence items is one node; the evidence list shows the link
    edges.push({ id: r.id, source: s, target: t, label: r.relationship_type.replace(/_/g, ' '), relationship_type: r.relationship_type,
      explanation: r.explanation, supporting_evidence_id: r.supporting_evidence_id });
  }
  const arr = [...nodes.values()].map((n) => ({ ...n, evidence_ids: [...n.evidence_ids], evidence_types: [...n.evidence_types] }));
  res.json({ ok: true, mode: 'real', label: 'REAL ANALYSIS', data: { nodes: arr, edges } });
};

exports.getTimeline = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { rows } = await query(
    `SELECT ev.*, e.evidence_type, e.source_identifier FROM investigation_events ev
     LEFT JOIN evidence e ON e.id = ev.evidence_id
     WHERE ev.investigation_id=$1
     ORDER BY ev.timestamp_known DESC, ev.event_timestamp ASC, ev.created_at ASC`, [inv.id]);
  res.json({ ok: true, mode: 'real', data: rows.map((r) => ({ ...r, timestamp_label: r.timestamp_known ? null : 'Unknown time' })) });
};

exports.loadCase = loadCase;
exports.getInvestigationOr404 = getInvestigationOr404;
