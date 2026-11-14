'use strict';
// Builds relationships ONLY where the stored evidence supports them.
// Rule A: the same value (phone/url/domain/upi/email/phrase) appears in 2+ different evidence items.
// Rule B: a URL entity and its own domain appear in the same evidence item.
// Rule C: a phone/url/upi/email appears in the same evidence item as another such identifier.
// No relationship is created from similarity, guesses or AI.

const LINKABLE = ['phone', 'url', 'domain', 'upi', 'email', 'phrase'];
const IDENTIFIERS = ['phone', 'url', 'upi', 'email'];
const LABELS = { phone: 'phone number', url: 'URL', domain: 'domain', upi: 'UPI identifier', email: 'email address', phrase: 'suspicious phrase' };

function evLabel(ev) { return ev ? `${ev.evidence_type.toUpperCase()} evidence ${ev.id.slice(0, 8)}` : 'evidence'; }

function buildRelationships(investigationId, evidenceList, entities) {
  const evById = new Map(evidenceList.map((e) => [e.id, e]));
  const rels = [];
  const key = new Set();
  const add = (a, b, type, explanation, supportingId) => {
    if (a.id === b.id) return;
    const k = [a.id, b.id].sort().join('|') + type;
    if (key.has(k)) return;
    key.add(k);
    rels.push({ investigation_id: investigationId, source_entity_id: a.id, target_entity_id: b.id,
      relationship_type: type, explanation, supporting_evidence_id: supportingId });
  };

  // Rule A: same value across different evidence
  const groups = new Map();
  for (const e of entities.filter((x) => LINKABLE.includes(x.entity_type))) {
    const k = e.entity_type + '|' + e.normalized_value;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(e);
  }
  for (const group of groups.values()) {
    const distinct = [...new Map(group.map((e) => [e.evidence_id, e])).values()];
    if (distinct.length < 2) continue;
    for (let i = 1; i < distinct.length; i++) {
      const a = distinct[i - 1], b = distinct[i];
      add(a, b, 'same_' + a.entity_type,
        `The same ${LABELS[a.entity_type]} "${a.entity_value}" appears in ${evLabel(evById.get(a.evidence_id))} and ${evLabel(evById.get(b.evidence_id))}.`,
        b.evidence_id);
    }
  }

  // Rules B and C: within one evidence item
  const byEvidence = new Map();
  for (const e of entities) { if (!byEvidence.has(e.evidence_id)) byEvidence.set(e.evidence_id, []); byEvidence.get(e.evidence_id).push(e); }
  for (const [evId, list] of byEvidence) {
    const ev = evById.get(evId);
    for (const u of list.filter((x) => x.entity_type === 'url')) {
      const d = list.find((x) => x.entity_type === 'domain' && u.entity_value.toLowerCase().includes(x.normalized_value));
      if (d) add(u, d, 'url_has_domain', `The domain "${d.entity_value}" is part of the URL "${u.entity_value}" in ${evLabel(ev)}.`, evId);
    }
    const ids = list.filter((x) => IDENTIFIERS.includes(x.entity_type));
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
      add(ids[i], ids[j], 'appears_together',
        `The ${LABELS[ids[i].entity_type]} "${ids[i].entity_value}" and the ${LABELS[ids[j].entity_type]} "${ids[j].entity_value}" appear together in ${evLabel(ev)}. This shows they were sent together, not that they belong to the same person.`,
        evId);
    }
  }
  return rels;
}

const TYPE_VERB = { sms: 'SMS received/submitted', whatsapp: 'WhatsApp conversation submitted', url: 'Suspicious URL submitted',
  upi: 'Payment request / UPI identifier submitted', screenshot: 'Screenshot submitted', note: 'Note added' };

function buildTimeline(investigationId, evidenceList, entities) {
  const events = evidenceList.map((ev) => {
    const ents = entities.filter((e) => e.evidence_id === ev.id && e.entity_type !== 'date');
    const names = ents.filter((e) => ['phone', 'url', 'upi', 'email'].includes(e.entity_type)).map((e) => e.entity_value);
    const known = !!ev.incident_timestamp;
    return {
      investigation_id: investigationId, evidence_id: ev.id,
      event_description: TYPE_VERB[ev.evidence_type] + (names.length ? ' — mentions ' + names.join(', ') : ''),
      event_timestamp: known ? new Date(ev.incident_timestamp).toISOString() : null,
      timestamp_known: known,
      _sort: known ? new Date(ev.incident_timestamp).getTime() : Infinity,
      _created: new Date(ev.created_at || 0).getTime(),
    };
  });
  events.sort((a, b) => (a._sort - b._sort) || (a._created - b._created));
  return events.map(({ _sort, _created, ...rest }) => rest);
}

module.exports = { buildRelationships, buildTimeline };
