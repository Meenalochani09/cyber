'use strict';
const PDFDocument = require('pdfkit');

const fmt = (d) => (d ? new Date(d).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : 'Unknown time');

// Builds the report data from stored records only. Observations and interpretations are kept separate.
function buildReportData({ investigation, evidence, entities, relationships, events, risk }) {
  const types = new Set(evidence.map((e) => e.evidence_type));
  const missing = [];
  if (!types.has('sms') && !types.has('whatsapp')) missing.push('No SMS or WhatsApp message has been submitted.');
  if (!types.has('url')) missing.push('No URL evidence submitted separately. Links inside messages are extracted, but no link was opened or scanned.');
  if (!types.has('upi')) missing.push('No payment request or UPI identifier evidence submitted.');
  evidence.filter((e) => !e.incident_timestamp).forEach((e) => missing.push(`Time of ${e.evidence_type.toUpperCase()} evidence ${e.id.slice(0, 8)} is unknown.`));
  evidence.filter((e) => e.processing_status === 'manual_entry_required').forEach((e) => missing.push(`Screenshot ${e.id.slice(0, 8)} has no extracted text. Type the visible text in to analyse it.`));

  return {
    case_id: investigation.id, case_name: investigation.case_name, description: investigation.case_description,
    generated_at: new Date().toISOString(), analysis_mode: investigation.analysis_mode,
    evidence_inventory: evidence.map((e) => ({ id: e.id, type: e.evidence_type, source: e.source_identifier, time: e.incident_timestamp, status: e.processing_status, excerpt: (e.original_text || '').slice(0, 300) })),
    entities: entities.map((e) => ({ type: e.entity_type, value: e.entity_value, evidence_id: e.evidence_id, method: e.extraction_method, note: e.explanation })),
    risk, relationships: relationships.map((r) => ({ type: r.relationship_type, explanation: r.explanation, evidence_id: r.supporting_evidence_id })),
    timeline: events,
    unverified: [
      'Phone numbers, UPI identifiers, websites and organisation names were NOT verified with any trusted source.',
      'Suspicious wording is an observation. It does not prove that a message or person is fraudulent.',
      'No URL was opened, visited or scanned.',
    ],
    missing_evidence: missing,
    recommended_actions: [
      'Do not share OTPs, PINs, passwords or card details with anyone who contacts you.',
      'Do not click the links or install any app suggested in these messages.',
      'Contact your bank only through the phone number printed on your card or in the official app.',
      'If money was sent, contact your bank immediately and report at cybercrime.gov.in or call 1930 (India).',
      'Keep the original messages and screenshots. Do not delete them.',
    ],
  };
}

function toPdf(report, res) {
  const doc = new PDFDocument({ margin: 50, size: 'A4', info: { Title: 'TRACELYT AI Investigation Report' } });
  doc.pipe(res);
  const H = (t) => { doc.moveDown(0.8).fontSize(14).fillColor('#0f172a').text(t).moveDown(0.3); doc.fontSize(10).fillColor('#1e293b'); };
  const P = (t) => doc.fontSize(10).fillColor('#1e293b').text(t, { lineGap: 2 });
  const B = (t) => doc.fontSize(10).fillColor('#1e293b').text('•  ' + t, { indent: 8, lineGap: 2 });

  doc.fontSize(20).fillColor('#0f172a').text('TRACELYT AI — Investigation Report');
  doc.fontSize(10).fillColor('#475569').text('Every Clue Connected. Every Threat Explained.');
  if (report.analysis_mode === 'demo') doc.fillColor('#b91c1c').text('FICTIONAL DEMO DATA — not a real investigation');
  doc.fillColor('#1e293b').moveDown();
  P(`Case ID: ${report.case_id}`); P(`Case name: ${report.case_name}`); P(`Generated: ${fmt(report.generated_at)}`);

  H('1. Investigation overview'); P(report.description || 'No description provided.');
  H('2. Evidence inventory');
  if (!report.evidence_inventory.length) P('No evidence submitted.');
  report.evidence_inventory.forEach((e) => B(`[${e.type.toUpperCase()} ${e.id.slice(0, 8)}] ${fmt(e.time)} | status: ${e.status}${e.source ? ' | source: ' + e.source : ''}\n    "${e.excerpt}"`));
  H('3. Extracted entities (observations)');
  if (!report.entities.length) P('None extracted.');
  report.entities.forEach((e) => B(`${e.type}: ${e.value} (evidence ${e.evidence_id.slice(0, 8)}, method: ${e.method})`));
  H('4. Risk indicators (interpretation)');
  P(`Assessment: ${report.risk.risk_label}. ${report.risk.method}`);
  report.risk.findings.forEach((f) => B(`${f.indicator} — "${f.supporting_evidence}" — ${f.reason} [${f.evidence_type.toUpperCase()} ${f.evidence_id.slice(0, 8)}]`));
  H('5. Relationships between evidence');
  if (!report.relationships.length) P('No relationships were found that the submitted evidence supports.');
  report.relationships.forEach((r) => B(r.explanation));
  H('6. Chronological timeline');
  report.timeline.forEach((t) => B(`${t.timestamp_known ? fmt(t.event_timestamp) : 'Unknown time'} — ${t.event_description}`));
  H('7. Unverified information'); report.unverified.forEach(B);
  H('8. Missing evidence'); (report.missing_evidence.length ? report.missing_evidence : ['None identified.']).forEach(B);
  H('9. Recommended safety actions'); report.recommended_actions.forEach(B);
  doc.moveDown().fontSize(8).fillColor('#64748b').text('This report lists observations and rule-based indicators from submitted evidence. It is not legal advice and does not confirm that any person or organisation committed fraud.');
  doc.end();
}

module.exports = { buildReportData, toPdf };
