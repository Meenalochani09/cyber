'use strict';
/* TRACELYT insight layer
   Explainable risk, evidence tracing, graph drill-down and case summary.
   Everything here is DERIVED from data the backend already returns (findings, entities, graph,
   evidence). It does not change or invent any scoring. Field access is defensive because the
   backend payloads can differ slightly between versions. Relies on globals from app.js
   (state, esc, fmtDate, pageHead, btn, riskName) at call time only. */

const TYPE_COLOR = { url: '#ff8d91', domain: '#f2a5a8', phone: '#85b6ff', upi: '#20d6cc', email: '#8fd1ff', phrase: '#eabf79', date: '#9aa9b9', name: '#c4a8ff', organisation: '#c4a8ff' };
const typeColor = t => TYPE_COLOR[t] || '#57dfb1';
const lc = s => String(s ?? '').toLowerCase();
const pl = (n, w, w2) => `${n} ${n === 1 ? w : (w2 || w + 's')}`;
const nice = s => String(s ?? '').replace(/_/g, ' ');

/* ---------- risk tier ---------- */
function riskTier(r) {
  if (!r) return 'none';
  // The backend computes risk live from stored entities, so "never analysed" is detected from evidence status.
  const ev = state.evidence || [];
  if (ev.some(e => e.processing_status === 'pending') && !ev.some(e => e.processing_status === 'processed')) return 'none';
  const l = lc(r.risk_level || '') + ' ' + lc(r.risk_label || '');
  if (/high|severe|critical/.test(l)) return 'high';
  if (/needs|verif|med|moder/.test(l)) return 'medium';
  if (/insufficient/.test(l)) return 'insufficient';
  if (/low|minimal|none/.test(l)) return 'low';
  return r.risk_level ? 'medium' : 'none';
}
const riskClass = r => ({ high: 'danger', medium: 'warn', low: 'good', insufficient: '', none: '' }[riskTier(r)]);
const pendingEvidence = () => (state.evidence || []).filter(e => e.processing_status === 'pending' && String(e.original_text || '').trim());

/* ---------- unified entities (graph nodes + /entities) ---------- */
function unifyEntities() {
  const map = new Map();
  const put = (type, value, norm, o) => {
    if (value === undefined || value === null || value === '') return;
    const t = lc(type) || 'other', k = t + '|' + lc(norm ?? value);
    let e = map.get(k);
    if (!e) { e = { key: k, id: null, type: t, value: String(value), variants: new Set(), evidenceIds: new Set(), reasons: [] }; map.set(k, e); }
    e.variants.add(String(value));
    if (o.id !== undefined && o.id !== null) e.id = o.id;
    (o.evidenceIds || []).forEach(i => e.evidenceIds.add(i));
    (o.reasons || []).forEach(r => { if (r && !e.reasons.includes(r)) e.reasons.push(r); });
  };
  // Graph node ids are "<type>|<normalized_value>", which is how nodes and /entities rows are matched.
  (state.graph?.nodes || []).forEach(n => {
    const id = String(n.id), pre = String(n.entity_type) + '|';
    put(n.entity_type, n.label, id.startsWith(pre) ? id.slice(pre.length) : n.label, { id: n.id, evidenceIds: n.evidence_ids, reasons: n.explanations });
  });
  (state.entities || []).forEach(x => put(x.entity_type || x.type, x.entity_value ?? x.value ?? x.label, x.normalized_value ?? x.entity_value,
    { evidenceIds: [x.evidence_id].filter(Boolean), reasons: [x.explanation || x.reason].filter(Boolean) }));
  return [...map.values()];
}
const entitiesOfEvidence = (ents, evId) => ents.filter(e => e.evidenceIds.has(evId));

/* ---------- locating entity text inside the original evidence ---------- */
function candidatePatterns(e) {
  const v = e.value, out = [v];
  if (e.type === 'phone') {
    const core = v.replace(/\D/g, '').slice(-10);
    if (core.length >= 8) out.push(new RegExp('(?:\\+?\\d{1,3}[\\s-]*)?' + core.split('').join('[\\s-]*'), 'gi'));
  }
  if (e.type === 'url') {
    try { out.push(new URL(/^https?:/i.test(v) ? v : 'http://' + v).hostname.replace(/^www\./, '')); } catch (_) { /* not a URL */ }
  }
  return out;
}
function locate(text, ents) {
  const raw = String(text || ''), low = raw.toLowerCase(), ranges = [];
  ents.forEach(e => {
    for (const p of [...e.variants].flatMap(v => candidatePatterns({ ...e, value: v }))) {
      if (typeof p === 'string') {
        const q = p.toLowerCase(); if (!q) continue;
        for (let i = low.indexOf(q); i !== -1; i = low.indexOf(q, i + q.length)) ranges.push({ s: i, e: i + q.length, ent: e });
      } else { p.lastIndex = 0; let m; while ((m = p.exec(raw))) { ranges.push({ s: m.index, e: m.index + m[0].length, ent: e }); if (!m[0].length) p.lastIndex++; } }
    }
  });
  return ranges.map(r => ({ ...r, cls: 'ent', style: `--c:${typeColor(r.ent.type)}`, title: `${r.ent.type}: ${r.ent.value}`, node: r.ent.id }));
}
function resolveOverlaps(ranges) {
  const out = [];
  [...ranges].sort((a, b) => a.s - b.s || (b.e - b.s) - (a.e - a.s)).forEach(r => { if (!out.length || r.s >= out[out.length - 1].e) out.push(r); });
  return out;
}
function markup(text, ranges) {
  const raw = String(text || ''); let out = '', i = 0;
  resolveOverlaps(ranges).forEach(r => {
    const node = r.node !== null && r.node !== undefined && r.node !== '' ? ` data-node="${esc(r.node)}" role="button" tabindex="0"` : '';
    out += esc(raw.slice(i, r.s)) + `<mark class="${r.cls}" style="${r.style || ''}" title="${esc(r.title || '')}"${node}>${esc(raw.slice(r.s, r.e))}</mark>`;
    i = r.e;
  });
  return out + esc(raw.slice(i));
}
function evidenceTextHtml(e, ents) {
  const t = e.original_text;
  if (!String(t || '').trim()) return '<span class="muted">No text stored for this item. Screenshot OCR is not installed; enter the visible text manually to analyse it.</span>';
  return markup(t, locate(t, entitiesOfEvidence(ents, e.id)));
}

/* ---------- findings <-> evidence ---------- */
function findingSource(f) {
  const ev = state.evidence || [];
  const ids = [].concat(f.evidence_id || f.evidence_ids || []).filter(Boolean);
  let hits = ev.filter(e => ids.includes(e.id)), how = 'evidence ID';
  const q = String(f.supporting_evidence || '').trim();
  if (!hits.length && q.length >= 3) { hits = ev.filter(e => lc(e.original_text).includes(lc(q)) || lc(e.source_identifier) === lc(q)); how = 'text match'; }
  if (!hits.length && f.evidence_type) { const same = ev.filter(e => e.evidence_type === f.evidence_type); if (same.length === 1) { hits = same; how = 'evidence type (only one of this type)'; } }
  return { items: hits, how: hits.length ? how : 'unresolved', quote: q };
}
const findingsOfEvidence = evId => (state.risk?.findings || []).filter(f => findingSource(f).items.some(e => e.id === evId));
const evMeta = e => `${esc(String(e.evidence_type || '').toUpperCase())} · ${esc(e.source_identifier || 'Unlabelled source')} · ${fmtDate(e.incident_timestamp || e.created_at)}`;

/* ---------- risk explanation ---------- */
function riskBreakdown() {
  const fs = state.risk?.findings || [], cats = new Map(), evIds = new Set(), channels = new Set();
  let unresolved = 0;
  fs.forEach(f => {
    const k = f.category || 'Uncategorised';
    if (!cats.has(k)) cats.set(k, []);
    cats.get(k).push(f);
    const src = findingSource(f);
    if (!src.items.length) unresolved++;
    src.items.forEach(e => { evIds.add(e.id); channels.add(e.evidence_type); });
  });
  return { fs, cats: [...cats.entries()].sort((a, b) => b[1].length - a[1].length), evIds, channels: [...channels], unresolved };
}
function riskHeadline() {
  const r = state.risk, tier = riskTier(r);
  if (tier === 'none') return 'No assessment yet. Add evidence and run the analysis.';
  const b = riskBreakdown();
  if (!b.fs.length) return `Rated ${riskName(r)}: the rule set found no indicators in the ${pl(state.evidence.length, 'evidence item')} analysed. This is not proof the content is safe.`;
  const cat = b.cats.map(([k]) => nice(k)).slice(0, 4).join(', ');
  const where = b.evIds.size ? ` in ${b.evIds.size} of ${pl(state.evidence.length, 'evidence item')}` : '';
  const ch = b.channels.length > 1 ? `, across ${b.channels.length} channels (${b.channels.join(', ')})` : '';
  return `Rated ${riskName(r)} because ${pl(b.fs.length, 'indicator')} fired${where}${ch}. Categories: ${cat}${b.cats.length > 4 ? ', …' : ''}.`;
}
const NOT_CHECKED = [
  'Live threat-intelligence or blocklist lookups',
  'Domain age, WHOIS or website content scanning',
  'Phone-number or UPI-handle ownership verification',
  'Bank, telecom or police confirmation of any identifier'
];

function findingCard(f) {
  const src = findingSource(f), ents = unifyEntities();
  const ev = src.items[0];
  let body;
  if (ev) {
    const t = String(ev.original_text || ''), q = src.quote, i = q.length >= 3 ? lc(t).indexOf(lc(q)) : -1;
    const ranges = i >= 0 ? [{ s: i, e: i + q.length, cls: 'hit', title: 'Text that triggered this rule' }] : locate(t, entitiesOfEvidence(ents, ev.id));
    const chips = entitiesOfEvidence(ents, ev.id).map(e => `<button class="entchip" ${e.id !== null ? `data-node="${esc(e.id)}"` : ''} style="--c:${typeColor(e.type)}" title="Open in relationship graph">${esc(e.type)} · ${esc(e.value.slice(0, 28))}</button>`).join('');
    body = `<div class="src"><div class="small">SOURCE · ${evMeta(ev)} · linked by ${esc(src.how)}${src.items.length > 1 ? ` · +${src.items.length - 1} more` : ''}</div>
      <div class="evidence-text" style="margin-top:6px">${t.trim() ? markup(t, ranges) : '<span class="muted">No text stored.</span>'}</div>
      <div class="row" style="margin-top:8px"><button class="btn" data-trace="${esc(ev.id)}">Trace to source →</button>${chips}</div></div>`;
  } else {
    body = `<div class="small">Source evidence could not be resolved from the API response. Backend says: ${esc(f.evidence_type || 'n/a')} · ${esc(f.supporting_evidence || 'n/a')}</div>`;
  }
  const sev = f.severity ?? f.weight ?? f.confidence;
  return `<div class="finding"><strong>${esc(f.indicator)} <span class="pill">${esc(f.rule_id || 'rule')}</span>${sev !== undefined && sev !== null ? ` <span class="pill">weight ${esc(sev)}</span>` : ''}</strong>
    <p><b>Why it was flagged:</b> ${esc(f.reason)}</p>${body}</div>`;
}

function threatPage() {
  const r = state.risk, tier = riskTier(r), b = riskBreakdown(), max = Math.max(1, ...b.cats.map(c => c[1].length));
  const relCount = state.graph?.edges?.length || 0;
  const drivers = tier === 'none' ? '' : `<div class="grid drivers">
    <div class="driver"><div class="statlabel">INDICATORS FIRED</div><div class="statvalue">${b.fs.length}</div><div class="small">${pl(b.cats.length, 'category', 'categories')}</div></div>
    <div class="driver"><div class="statlabel">EVIDENCE CORROBORATING</div><div class="statvalue blue">${b.evIds.size}<span class="of"> / ${state.evidence.length}</span></div><div class="small">${b.channels.length ? esc(b.channels.join(' · ')) : 'sources not resolved'}</div></div>
    <div class="driver"><div class="statlabel">LINKED IDENTIFIERS</div><div class="statvalue cyan">${relCount}</div><div class="small">shared-identifier relationships</div></div></div>`;
  const bars = b.cats.map(([k, list]) => `<div class="catrow"><span>${esc(nice(k))}</span><div class="catbar"><i style="width:${Math.round(list.length / max * 100)}%"></i></div><b>${list.length}</b></div>`).join('');
  const groups = b.cats.map(([k, list]) => `<details class="group" open><summary><b>${esc(nice(k))}</b> <span class="pill">${pl(list.length, 'indicator')}</span></summary><div class="findings">${list.map(findingCard).join('')}</div></details>`).join('');
  return `${pageHead('ANALYTICS / EXPLAINABLE RISK', 'Threat Findings', 'Every indicator below is traceable to the evidence that triggered it.', `<span class="chip ${riskClass(r)}">${esc(riskName(r)).toUpperCase()}</span>`)}
  <div class="card verdict ${riskClass(r)}"><div class="statlabel">WHY THIS RATING</div><p class="headline">${esc(riskHeadline())}</p>${r?.rating_basis?.explanation ? `<p class="basis"><b>Rule applied:</b> ${esc(r.rating_basis.explanation)}</p>` : ''}${drivers}${bars ? `<div class="cats">${bars}</div>` : ''}</div>
  <div class="card" style="margin-top:14px"><div class="section-title"><h2>Findings by category</h2><span class="pill">${pl(b.fs.length, 'observation')}</span></div>${groups || '<div class="empty">No findings yet. Run analysis after adding evidence.</div>'}${b.unresolved ? `<p class="small">${pl(b.unresolved, 'finding')} could not be matched to a specific evidence item from the API response.</p>` : ''}</div>
  <div class="grid two-col" style="margin-top:14px"><div class="card"><h2>Assessment method</h2><p>${esc(r?.method || 'No assessment available yet.')}</p><div class="notice">This is a rule-based indicator assessment, not a probability of fraud and not a legal finding. A high-concern label does not prove that a sender, account or person is malicious.</div></div>
  <div class="card"><h3>Not checked by this assessment</h3><ul class="plain">${NOT_CHECKED.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></div>`;
}

/* ---------- evidence verification (used by evidencePage) ---------- */
function verifyPanel(e) {
  const ents = unifyEntities(), mine = entitiesOfEvidence(ents, e.id), fs = findingsOfEvidence(e.id), t = String(e.original_text || '');
  const rows = mine.map(x => {
    const lit = locate(t, [x]).length > 0;
    return `<div class="entrow" style="--c:${typeColor(x.type)}"><div class="row"><span class="chip" style="color:${typeColor(x.type)};border-color:${typeColor(x.type)}">${esc(x.type.toUpperCase())}</span><span class="mono wrap" style="flex:1;min-width:0">${esc(x.value)}</span>${x.id !== null ? `<button class="btn" data-node="${esc(x.id)}">Graph</button>` : ''}</div><div class="why"><b>Why detected:</b> ${esc(x.reasons.join(' ') || 'Matched an extraction rule (reason not supplied by API)')}</div><div class="small">${lit ? '<span class="ok">✓ value found in original text</span>' : 'Normalised value, not found verbatim in the text'}</div></div>`;
  }).join('');
  return `<div class="verify">
    <div class="statlabel">ORIGINAL MESSAGE · HIGHLIGHTED = EXTRACTED ENTITIES (CLICK TO OPEN IN GRAPH)</div>
    <div class="evidence-text" style="margin:6px 0 12px">${evidenceTextHtml(e, ents)}</div>
    <div class="statlabel">EXTRACTED ENTITIES · ${mine.length}</div>
    ${mine.length ? rows : '<p class="small">No entities extracted from this item yet. Run the analysis, or the item contains no recognised identifiers.</p>'}
    <div class="statlabel" style="margin-top:12px">RISK INDICATORS FROM THIS EVIDENCE · ${fs.length}</div>
    ${fs.length ? fs.map(f => `<div class="finding"><strong>${esc(f.indicator)} <span class="pill">${esc(nice(f.category))}</span></strong><p>${esc(f.reason)}</p></div>`).join('') : '<p class="small">None attributed to this item.</p>'}
    <div class="small" style="margin-top:10px">Evidence ID ${esc(e.id)} · status ${esc(e.processing_status || 'n/a')} · recorded ${fmtDate(e.created_at)} · incident time ${e.incident_timestamp ? fmtDate(e.incident_timestamp) : 'not provided'}</div></div>`;
}
function evidenceBadges(e) {
  const ents = unifyEntities(), n = entitiesOfEvidence(ents, e.id).length, f = findingsOfEvidence(e.id).length;
  return e.processing_status === 'pending' ? '<span class="pill">not analysed</span>' : `<span class="pill">${pl(n, 'entity', 'entities')}</span><span class="pill">${pl(f, 'indicator')}</span>`;
}

/* ---------- relationship graph with drill-down ---------- */
function graphPage() {
  const g = state.graph, nodes = g?.nodes || [], edges = g?.edges || [], ents = unifyEntities();
  const sel = nodes.find(n => String(n.id) === String(state.selNode)) ? String(state.selNode) : null;
  const nb = new Set(); if (sel) edges.forEach(e => { if (String(e.source) === sel) nb.add(String(e.target)); if (String(e.target) === sel) nb.add(String(e.source)); });
  let svg = '';
  if (nodes.length) {
    const cx = 450, cy = 255, rad = Math.min(200, 125 + nodes.length * 9), pos = {};
    nodes.forEach((n, i) => { const a = Math.PI * 2 * i / nodes.length - Math.PI / 2; pos[n.id] = [cx + rad * Math.cos(a), cy + rad * Math.sin(a)]; });
    const touches = e => !sel || String(e.source) === sel || String(e.target) === sel;
    svg = `<rect width="900" height="530" fill="transparent" data-node-clear="1"/>` + edges.map(e => {
      const a = pos[e.source], b = pos[e.target]; if (!a || !b) return '';
      return `<g class="${touches(e) ? '' : 'dim'}"><line x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}" stroke="${sel && touches(e) ? '#ffd27a' : '#20cfc9'}" stroke-width="${sel && touches(e) ? 3 : 2}" opacity=".7"/><text x="${(a[0] + b[0]) / 2}" y="${(a[1] + b[1]) / 2 - 7}" text-anchor="middle" class="edge-label">${esc(nice(e.label))}</text></g>`;
    }).join('') + nodes.map(n => {
      const [x, y] = pos[n.id], c = typeColor(n.entity_type), id = String(n.id), on = id === sel, dim = sel && !on && !nb.has(id);
      return `<g class="gnode ${dim ? 'dim' : ''} ${on ? 'sel' : ''}" data-node="${esc(id)}" role="button" tabindex="0" aria-label="${esc(n.entity_type + ' ' + n.label)}"><title>${esc(n.entity_type + ': ' + n.label)} — click for evidence</title><circle cx="${x}" cy="${y}" r="${on ? 31 : 27}" fill="${c}" fill-opacity="${on ? .38 : .18}" stroke="${c}" stroke-width="${on ? 4 : 2}"/><text x="${x}" y="${y + 4}" text-anchor="middle" class="node-label">${esc(String(n.entity_type).slice(0, 5).toUpperCase())}</text><text x="${x}" y="${y + 46}" text-anchor="middle" class="edge-label">${esc(String(n.label).slice(0, 23))}</text></g>`;
    }).join('');
  }
  const legend = [...new Set(nodes.map(n => n.entity_type))].map(t => `<span class="lg"><i style="background:${typeColor(t)}"></i>${t}</span>`).join('');
  const side = sel ? nodePanel(sel, edges, ents) : `<h2>Graph Summary</h2><div class="row"><div><div class="statvalue cyan">${nodes.length}</div><div class="statlabel">ENTITY NODES</div></div><div style="margin-left:18px"><div class="statvalue blue">${edges.length}</div><div class="statlabel">RELATIONSHIPS</div></div></div>
    <div class="notice" style="margin:14px 0">Click any node to see its supporting evidence, why it was detected and what it connects to.</div>
    <h3>Entity Registry</h3>${nodes.length ? nodes.map(n => `<button class="evidence-card regbtn" data-node="${esc(n.id)}"><b class="wrap">${esc(n.label)}</b><div class="small">${esc(n.entity_type)} · seen in ${(n.evidence_ids || []).length} evidence item(s)</div></button>`).join('') : '<p class="muted">Entity details will appear here.</p>'}
    <p class="small">Links come from the backend's shared-identifier rules. A relationship does not establish common ownership or criminal identity.</p>`;
  return `${pageHead('ANALYTICS & GRAPH / REAL CASE DATA', 'Interactive Forensic Relationship Graph', state.current ? esc(state.current.case_name) : 'Select a case to inspect its graph.', `<span class="chip">${nodes.length} NODES</span><span class="chip">${edges.length} EDGES</span>`)}
  <div class="graph-layout"><div class="graphbox">${nodes.length ? `<svg viewBox="0 0 900 530" role="group" aria-label="Relationship graph">${svg}</svg><div class="legend">${legend}</div>` : '<div class="empty" style="margin:24px">No graph data yet. Add evidence and run analysis.</div>'}</div><div class="graph-side">${side}</div></div>`;
}
function nodePanel(sel, edges, ents) {
  const n = state.graph.nodes.find(x => String(x.id) === sel), ent = ents.find(x => String(x.id) === sel) || { evidenceIds: new Set(n.evidence_ids || []), reasons: n.explanations || [] };
  const evs = (state.evidence || []).filter(e => ent.evidenceIds.has(e.id));
  const links = edges.filter(e => String(e.source) === sel || String(e.target) === sel).map(e => {
    const oid = String(e.source) === sel ? e.target : e.source, o = state.graph.nodes.find(x => String(x.id) === String(oid));
    return { e, o };
  }).filter(x => x.o);
  const all = state.risk?.findings || [], direct = all.filter(f => f.entity_key && String(f.entity_key).toLowerCase() === sel.toLowerCase());
  const fs = [...direct, ...all.filter(f => !direct.includes(f) && findingSource(f).items.some(it => ent.evidenceIds.has(it.id)))];
  const c = typeColor(n.entity_type);
  return `<div class="row"><span class="chip" style="color:${c};border-color:${c}">${esc(String(n.entity_type).toUpperCase())}</span><button class="btn" data-node-clear="1" style="margin-left:auto">✕ Clear</button></div>
    <h2 class="wrap" style="margin-top:12px">${esc(n.label)}</h2>
    <div class="small">Seen in ${pl(evs.length, 'evidence item')} · connected to ${pl(links.length, 'other entity', 'other entities')}</div>
    <div class="statlabel sec">WHY IT WAS DETECTED</div>
    ${(ent.reasons.length ? ent.reasons : ['Reason not supplied by the API.']).map(r => `<p class="rs">${esc(r)}</p>`).join('')}
    <div class="statlabel sec">SUPPORTING EVIDENCE · ${evs.length}</div>
    ${evs.length ? evs.map(e => `<div class="evidence-card"><div class="small">${evMeta(e)}</div><div class="evidence-text" style="margin-top:6px">${evidenceTextHtml(e, ents)}</div><button class="btn" style="margin-top:8px" data-trace="${esc(e.id)}">Verify in Evidence Vault →</button></div>`).join('') : '<p class="small">No evidence item resolved for this node.</p>'}
    <div class="statlabel sec">CONNECTED ENTITIES · ${links.length}</div>
    ${links.length ? links.map(({ e, o }) => `<div class="evidence-card"><button class="linkbtn" data-node="${esc(o.id)}"><span class="chip" style="color:${typeColor(o.entity_type)}">${esc(o.entity_type)}</span> <b class="wrap">${esc(o.label)}</b></button><div class="small" style="margin-top:7px"><b>${esc(nice(e.label))}</b>${e.explanation || e.reason ? ' — ' + esc(e.explanation || e.reason) : ''}</div>${e.supporting_evidence_id ? `<button class="btn" style="margin-top:8px" data-trace="${esc(e.supporting_evidence_id)}">View supporting evidence →</button>` : ''}</div>`).join('') : '<p class="small">Not linked to any other entity.</p>'}
    <div class="statlabel sec">RELATED RISK INDICATORS · ${fs.length}</div>
    ${fs.length ? fs.map(f => `<div class="finding"><strong>${esc(f.indicator)} ${direct.includes(f) ? '<span class="pill">triggered by this entity</span>' : '<span class="pill">same evidence</span>'}</strong><p>${esc(f.reason)}</p></div>`).join('') : '<p class="small">None attributed to this entity\'s evidence.</p>'}`;
}

/* ---------- investigation summary ---------- */
function flaggedEntities() {
  const ents = unifyEntities(), edges = state.graph?.edges || [];
  return ents.filter(e => ['phone', 'url', 'upi', 'email'].includes(e.type)).map(e => {
    const why = [], evs = (state.evidence || []).filter(x => e.evidenceIds.has(x.id));
    const inds = [...new Set(evs.flatMap(x => findingsOfEvidence(x.id).map(f => f.indicator)))];
    if (inds.length) why.push(`In evidence that triggered: ${inds.slice(0, 3).join('; ')}${inds.length > 3 ? '…' : ''}`);
    if (e.evidenceIds.size > 1) why.push(`Reused across ${e.evidenceIds.size} evidence items`);
    const links = e.id === null ? 0 : edges.filter(x => String(x.source) === String(e.id) || String(x.target) === String(e.id)).length;
    if (links) why.push(`Linked to ${pl(links, 'other identifier')}`);
    return { ...e, why, score: why.length * 10 + e.evidenceIds.size };
  }).filter(e => e.why.length).sort((a, b) => b.score - a.score);
}
function nextActions() {
  const c = state.current, ev = state.evidence || [], tier = riskTier(state.risk), ents = unifyEntities(), has = t => ents.filter(e => e.type === t);
  if (!c) return [{ t: 'Create an investigation', d: 'Start a case to hold your evidence.', go: 'new', label: 'New Investigation' }];
  if (!ev.length) return [{ t: 'Add the first piece of evidence', d: 'Paste the SMS, WhatsApp message, URL or UPI ID you received.', go: 'evidence', label: 'Add Evidence' }];
  const A = [], blank = ev.filter(e => !String(e.original_text || '').trim());
  const blankAct = blank.length ? { t: `Enter the text of ${pl(blank.length, 'screenshot')}`, d: 'OCR is not installed, so screenshots cannot be analysed until their visible text is typed in.', go: 'evidence', label: 'Open Evidence Vault' } : null;
  if (tier === 'none') { A.push({ t: 'Run the analysis', d: 'Extract entities, link shared identifiers, build the timeline and assess risk indicators.', go: 'analyse', label: 'Run Analysis' }); if (blankAct) A.push(blankAct); return A; }
  const urls = has('url'), upis = has('upi'), phones = has('phone'), rel = state.graph?.edges?.length || 0;
  if (tier === 'high') {
    A.push({ t: 'Stop engaging and preserve the evidence', d: 'Do not reply, click links, install apps or send money. Keep the original messages, numbers and screenshots unedited.' });
    if (urls.length) A.push({ t: 'Do not open the flagged link' + (urls.length > 1 ? 's' : ''), d: urls.slice(0, 2).map(u => u.value).join(', ') + (urls.length > 2 ? '…' : '') });
    if (upis.length) A.push({ t: 'If any payment was made, contact your bank now', d: `Use the number on your card or official app and mention ${upis[0].value}. India cyber financial fraud helpline: 1930.` });
    if (phones.length) A.push({ t: 'Block the number' + (phones.length > 1 ? 's' : '') + ' and report via official channels', d: phones.slice(0, 2).map(p => p.value).join(', ') });
    A.push({ t: 'Report through the official portal', d: 'Include every linked identifier' + (rel ? ` (${pl(rel, 'relationship')} detected)` : '') + ' in the complaint.', go: 'portal', label: 'Open cybercrime portal' });
  } else if (tier === 'medium') {
    A.push({ t: 'Verify independently before acting', d: 'Contact the claimed organisation using a number from its official website or your card, never from the message.' });
    if (ev.length < 3) A.push({ t: 'Add corroborating evidence', d: 'More messages, URLs or UPI details let the rules cross-check identifiers.', go: 'evidence', label: 'Add Evidence' });
  } else {
    A.push({ t: 'No strong indicators found, stay cautious', d: 'The rule set may miss new tactics. If the request involves money or credentials, verify it through an official channel.' });
  }
  if (blankAct) A.push(blankAct);
  const pend = pendingEvidence();
  if (pend.length) A.unshift({ t: 'Re-run the analysis', d: `${pl(pend.length, 'evidence item')} added or edited since the last run, so the results above may be incomplete.`, go: 'analyse', label: 'Run Analysis' });
  A.push({ t: 'Export the investigation report', d: 'Download the PDF to keep or share with the bank or authorities.', go: 'pdf', label: 'Download PDF' });
  return A;
}
function caseFacts() {
  const ev = state.evidence || [], types = {};
  ev.forEach(e => { types[e.evidence_type] = (types[e.evidence_type] || 0) + 1; });
  const fl = flaggedEntities(), edges = state.graph?.edges || [], fs = state.risk?.findings || [];
  return { ev, types, fl, edges, fs, tier: riskTier(state.risk), acts: nextActions() };
}
function caseHeadline(f) {
  if (!state.current) return 'No case selected.';
  if (!f.ev.length) return 'This case has no evidence yet.';
  if (f.tier === 'none') return `${pl(f.ev.length, 'evidence item')} saved but not yet analysed.`;
  const pend = pendingEvidence().length;
  return `${pl(f.ev.length, 'evidence item')}: ${riskName(state.risk)}. ${pl(f.fs.length, 'indicator')} found, ${pl(f.fl.length, 'suspicious entity', 'suspicious entities')}, ${pl(f.edges.length, 'relationship')} between identifiers.${pend ? ` ${pl(pend, 'newer item')} not yet analysed.` : ''}`;
}
function actionBtn(a, primary) { return a.go ? `<button class="btn ${primary ? 'primary' : ''}" data-action="${a.go}">${esc(a.label || 'Go')}</button>` : ''; }

function summaryCompact() {
  const f = caseFacts(), a = f.acts[0];
  return `<div class="card summary ${riskClass(state.risk)}"><div class="section-title"><h2>Investigation Summary</h2><button class="btn" data-action="summary">Full summary →</button></div>
    <p class="headline">${esc(caseHeadline(f))}</p>
    ${a ? `<div class="nextaction"><div class="statlabel">RECOMMENDED NEXT ACTION</div><b>${esc(a.t)}</b><p>${esc(a.d)}</p>${actionBtn(a, true)}</div>` : ''}</div>`;
}
function summaryPage() {
  const f = caseFacts(), a = f.acts[0], ents = unifyEntities(), nodes = state.graph?.nodes || [];
  const typeStr = Object.entries(f.types).map(([k, v]) => `${v} ${k}`).join(' · ') || 'none';
  const byCat = riskBreakdown().cats;
  const relRows = f.edges.map(e => {
    const s = nodes.find(n => String(n.id) === String(e.source)), t = nodes.find(n => String(n.id) === String(e.target)); if (!s || !t) return '';
    return `<div class="rel"><button class="entchip" data-node="${esc(s.id)}" style="--c:${typeColor(s.entity_type)}">${esc(s.label.slice(0, 26))}</button><span class="small">— ${esc(nice(e.label))} —</span><button class="entchip" data-node="${esc(t.id)}" style="--c:${typeColor(t.entity_type)}">${esc(t.label.slice(0, 26))}</button></div>`;
  }).join('');
  const entRows = f.fl.slice(0, 8).map(e => `<tr><td><span class="chip" style="color:${typeColor(e.type)};border-color:${typeColor(e.type)}">${esc(e.type.toUpperCase())}</span></td><td class="mono wrap">${e.id !== null ? `<a href="#" data-node="${esc(e.id)}">${esc(e.value)}</a>` : esc(e.value)}</td><td>${esc(e.why.join(' · '))}</td></tr>`).join('');
  const tile = (l, v, s, cls = '') => `<div class="card"><div class="statlabel">${l}</div><div class="statvalue ${cls}">${v}</div><div class="statfoot">${s}</div></div>`;
  return `${pageHead('ANALYTICS / CASE SUMMARY', 'Investigation Summary', state.current ? esc(state.current.case_name) : 'Select a case first.', `<button class="btn" data-copy-summary="1">Copy as text</button>${btn('Download PDF', 'pdf', true)}`)}
  <div class="card summary ${riskClass(state.risk)}"><p class="headline">${esc(caseHeadline(f))}</p>${state.risk?.rating_basis?.explanation && f.tier !== 'none' ? `<p class="basis"><b>Rule applied:</b> ${esc(state.risk.rating_basis.explanation)}</p>` : ''}${a ? `<div class="nextaction"><div class="statlabel">RECOMMENDED NEXT ACTION</div><b>${esc(a.t)}</b><p>${esc(a.d)}</p>${actionBtn(a, true)}</div>` : ''}</div>
  <div class="grid stats five" style="margin-top:14px">${tile('EVIDENCE ITEMS', f.ev.length, esc(typeStr), 'blue')}${tile('SUSPICIOUS ENTITIES', f.fl.length, `of ${ents.length} extracted`, 'red')}${tile('RELATIONSHIPS', f.edges.length, 'shared-identifier links', 'cyan')}${tile('RISK LEVEL', `<span class="tier ${riskClass(state.risk)}">${esc(riskName(state.risk)).toUpperCase()}</span>`, 'rule-based, not a probability')}${tile('INDICATORS', f.fs.length, pl(byCat.length, 'category', 'categories'), 'amber')}</div>
  <div class="grid two-col"><div class="stack">
    <div class="card"><div class="section-title"><h2>Suspicious entities</h2><span class="pill">${f.fl.length}</span></div>${entRows ? `<div class="tablewrap"><table class="table"><thead><tr><th>TYPE</th><th>VALUE</th><th>WHY FLAGGED</th></tr></thead><tbody>${entRows}</tbody></table></div>${f.fl.length > 8 ? `<p class="small">+${f.fl.length - 8} more in the Relationship Graph.</p>` : ''}` : '<div class="empty">No entities flagged yet.</div>'}<p class="small">Flagged = present in evidence that triggered an indicator, reused across evidence, or linked to another identifier. It does not prove who owns an identifier.</p></div>
    <div class="card"><div class="section-title"><h2>Key indicators</h2><button class="btn" data-action="threat">All findings →</button></div>${byCat.length ? byCat.map(([k, list]) => `<div class="kv"><b>${esc(nice(k))}</b><span>${list.slice(0, 3).map(x => esc(x.indicator)).join(' · ')}${list.length > 3 ? ' …' : ''}</span></div>`).join('') : '<div class="empty">No indicators yet.</div>'}</div></div>
  <div class="stack"><div class="card"><h2>Detected relationships</h2>${relRows || '<p class="small">No shared-identifier relationships detected.</p>'}</div>
    <div class="card"><h2>Action plan</h2><ol class="plan">${f.acts.map(x => `<li><b>${esc(x.t)}</b><div class="small">${esc(x.d)}</div>${x.go ? actionBtn(x) : ''}</li>`).join('')}</ol></div></div></div>`;
}
function summaryText() {
  const f = caseFacts(), c = state.current;
  return ['TRACELYT AI — INVESTIGATION SUMMARY', `Case: ${c?.case_name || 'n/a'} (${String(c?.id || '').slice(0, 8)})`, `Risk level: ${riskName(state.risk)} (rule-based indicator assessment, not a fraud probability)`,
    `Evidence items: ${f.ev.length} (${Object.entries(f.types).map(([k, v]) => v + ' ' + k).join(', ') || 'none'})`,
    `Suspicious entities: ${f.fl.length}` + f.fl.slice(0, 8).map(e => `\n  - ${e.type}: ${e.value} (${e.why.join('; ')})`).join(''),
    `Relationships: ${f.edges.length}`, `Indicators: ${f.fs.length}` + f.fs.slice(0, 10).map(x => `\n  - [${nice(x.category)}] ${x.indicator}: ${x.reason}`).join(''),
    'Recommended actions:' + f.acts.map((x, i) => `\n  ${i + 1}. ${x.t} — ${x.d}`).join(''), '', 'Indicators are observations, not proof of fraud or of any person\'s identity.'].join('\n');
}

/* ---------- interactions ---------- */
function afterRender() {
  if (state.scrollTo) {
    const el = document.getElementById(state.scrollTo); state.scrollTo = null;
    if (el) { el.scrollIntoView({ block: 'center' }); el.classList.add('flash'); }
  }
}
document.addEventListener('click', async e => {
  const clr = e.target.closest('[data-node-clear]');
  const node = !clr && e.target.closest('[data-node]');
  if (node && node.dataset.node) { e.preventDefault(); state.selNode = node.dataset.node; state.page === 'graph' ? render() : setPage('graph'); return; }
  if (clr) { state.selNode = null; render(); return; }
  const tr = e.target.closest('[data-trace]');
  if (tr) { state.verifyId = tr.dataset.trace; state.scrollTo = 'ev-' + tr.dataset.trace; setPage('evidence'); return; }
  const vf = e.target.closest('[data-verify]');
  if (vf) { state.verifyId = state.verifyId === vf.dataset.verify ? null : vf.dataset.verify; render(); return; }
  if (e.target.closest('[data-copy-summary]')) {
    try { await navigator.clipboard.writeText(summaryText()); toast('Summary copied to clipboard.'); } catch (_) { toast('Clipboard blocked by the browser. Select the page text instead.'); }
  }
});
document.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches?.('[data-node][role=button]')) { e.preventDefault(); e.target.dispatchEvent(new MouseEvent('click', { bubbles: true })); }
});
