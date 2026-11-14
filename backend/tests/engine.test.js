'use strict';
const assert = require('assert');
const { extractFromEvidence } = require('../services/evidenceExtractor');
const { analyse } = require('../services/riskAnalyzer');
const { buildRelationships, buildTimeline } = require('../services/relationshipBuilder');

let n = 0; const t = (name, fn) => { fn(); n++; console.log('PASS', name); };
const id = (c) => c.repeat(8) + '-0000-4000-8000-000000000000';

t('spec example extraction', () => {
  const ents = extractFromEvidence({ id: id('a'), evidence_type: 'sms',
    original_text: 'Your bank KYC will expire today. Contact support at +919876543210. Verify your account at https://example-test.invalid' });
  const get = (type) => ents.filter((e) => e.entity_type === type).map((e) => e.entity_value);
  assert.deepStrictEqual(get('phone'), ['+919876543210']);
  assert.deepStrictEqual(get('url'), ['https://example-test.invalid']);
  assert.deepStrictEqual(get('domain'), ['example-test.invalid']);
  const keys = ents.filter((e) => e.entity_type === 'phrase').map((e) => e.normalized_value);
  assert(keys.includes('kyc_expiry') && keys.includes('verify_account'), 'phrases: ' + keys);
  assert(ents.every((e) => e.evidence_id === id('a')), 'source evidence id kept');
  assert.strictEqual(get('upi').length, 0); assert.strictEqual(get('email').length, 0);
});

t('does not invent entities from empty or clean text', () => {
  assert.strictEqual(extractFromEvidence({ id: id('b'), evidence_type: 'note', original_text: 'Had lunch with family on Sunday.' }).length, 0);
  assert.strictEqual(extractFromEvidence({ id: id('b'), evidence_type: 'note', original_text: '' }).length, 0);
});

t('upi vs email distinguished; phone not taken from inside upi', () => {
  const e = extractFromEvidence({ id: id('c'), evidence_type: 'upi', original_text: 'Pay Rs 1 to kyc.verify@okbank or mail help@example-bank.com or 9876543210@ybl' });
  const v = (ty) => e.filter((x) => x.entity_type === ty).map((x) => x.entity_value);
  assert.deepStrictEqual(v('email'), ['help@example-bank.com']);
  assert.deepStrictEqual(v('upi').sort(), ['9876543210@ybl', 'kyc.verify@okbank']);
  assert.strictEqual(v('phone').length, 0);
});

const evidence = [
  { id: id('1'), evidence_type: 'sms', original_text: 'Dear customer, your account will be blocked today. Call +91 98765 43210 or visit http://secure-bank-kyc-update.invalid/login', incident_timestamp: '2026-11-10T09:15:00Z', created_at: '2026-11-14T01:00:00Z' },
  { id: id('2'), evidence_type: 'whatsapp', original_text: 'Hello, I am from the bank support team. Share the OTP immediately. Confirm at http://secure-bank-kyc-update.invalid/login. Call 9876543210', incident_timestamp: '2026-11-10T11:40:00Z', created_at: '2026-11-14T01:01:00Z' },
  { id: id('3'), evidence_type: 'upi', original_text: 'kyc.verify@okbank Rs 10 verification fee', incident_timestamp: null, created_at: '2026-11-14T01:02:00Z' },
  { id: id('4'), evidence_type: 'note', original_text: 'Unrelated: electricity bill reminder from 080-12345678 - no link', incident_timestamp: null, created_at: '2026-11-14T01:03:00Z' },
];
const entities = evidence.flatMap(extractFromEvidence).map((e, i) => ({ ...e, id: id(String.fromCharCode(101 + (i % 20))) .replace(/^./, String(i % 10)) + '-' + i }));
// give each entity a unique uuid-like id
entities.forEach((e, i) => { e.id = `ent-${i}`; });

t('relationships only where evidence supports them', () => {
  const rels = buildRelationships('inv1', evidence, entities);
  const byId = new Map(entities.map((e) => [e.id, e]));
  const desc = rels.map((r) => `${r.relationship_type}:${byId.get(r.source_entity_id).entity_value}~${byId.get(r.target_entity_id).entity_value}`);
  console.log('  relationships:', desc);
  assert(rels.some((r) => r.relationship_type === 'same_url'), 'same URL linked across SMS and WhatsApp');
  assert(rels.some((r) => r.relationship_type === 'same_phone'), 'same phone (formatted differently) linked');
  assert(rels.every((r) => r.explanation && r.supporting_evidence_id), 'every relationship explained + traceable');
  const ev4 = new Set(entities.filter((e) => e.evidence_id === id('4')).map((e) => e.id));
  assert(!rels.some((r) => ev4.has(r.source_entity_id) && !ev4.has(r.target_entity_id)) && !rels.some((r) => ev4.has(r.target_entity_id) && !ev4.has(r.source_entity_id)), 'unrelated evidence NOT linked to the others');
});

t('risk analysis findings are traceable and never claim certainty', () => {
  const r = analyse(evidence, entities);
  console.log('  level:', r.risk_label, '| indicators:', r.findings.map((f) => f.rule_id));
  assert.strictEqual(r.risk_level, 'high_concern');
  assert(r.findings.every((f) => f.indicator && f.supporting_evidence && f.reason && f.evidence_id));
  const clean = analyse([evidence[3]], entities.filter((e) => e.evidence_id === id('4')));
  assert.strictEqual(clean.risk_level, 'insufficient_evidence');
  assert(!/fraud(ulent)? (probability|score)/i.test(JSON.stringify(r.method)) || /not a fraud probability/i.test(r.method));
});

t('timeline: real timestamps sorted, unknown labelled unknown', () => {
  const tl = buildTimeline('inv1', evidence, entities);
  assert.deepStrictEqual(tl.map((x) => x.evidence_id), [id('1'), id('2'), id('3'), id('4')]);
  assert.strictEqual(tl[2].timestamp_known, false); assert.strictEqual(tl[2].event_timestamp, null);
  assert.strictEqual(tl[0].timestamp_known, true);
});

t('risk rating explains itself and findings name the triggering entity', () => {
  const ev = [{ id: id('9'), evidence_type: 'sms', source_identifier: 'VM-BANK', original_text: 'Share your OTP urgently. Verify at http://hdfc-kyc-update.xyz/login' }];
  const r = analyse(ev, extractFromEvidence(ev[0]));
  assert.strictEqual(r.risk_level, 'high_concern');
  assert.strictEqual(r.rating_basis.triggered_by, 'credential_or_remote_access');
  assert(/OTP/.test(r.rating_basis.explanation));
  const u = r.findings.find((f) => f.rule_id === 'suspicious_url');
  assert(u && u.entity_key.startsWith('url|'), 'url finding carries its entity key');
  const none = analyse([{ id: id('8'), evidence_type: 'note', original_text: 'hello' }], []);
  assert.strictEqual(none.rating_basis.triggered_by, 'no_indicators');
});
console.log(`\n${n} tests passed`);
