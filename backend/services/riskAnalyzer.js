'use strict';
// Transparent, rule-based risk assessment.
// This is NOT a probability and NOT proof of fraud. Every finding names its rule,
// the supporting text, the reason for concern and the evidence it came from.

const SHORTENERS = ['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy', 'is.gd', 't.co', 'goo.gl', 'shorturl.at'];
const RISKY_TLDS = ['.xyz', '.top', '.click', '.icu', '.live', '.work', '.support', '.invalid', '.tk', '.ml', '.gq', '.cf'];
const BRAND_WORDS = ['bank', 'kyc', 'secure', 'verify', 'update', 'login', 'netbanking', 'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'upi'];

// Maps a phrase key from the extractor to a risk rule.
const PHRASE_RULES = {
  kyc_expiry: { id: 'kyc_claim', indicator: 'KYC expiry claim', category: 'impersonation_or_pressure', reason: 'Messages that claim KYC is expiring are a common pretext, but genuine banks also send KYC reminders. Verify through the bank\'s official app or branch.' },
  account_blocked: { id: 'account_block', indicator: 'Account-blocking claim', category: 'urgency', reason: 'Threatening to block an account is a pressure technique used to rush decisions.' },
  verify_account: { id: 'verify_request', indicator: 'Request to verify account details', category: 'credential', reason: 'Asking you to verify details through a message or link can be used to collect personal information.' },
  share_otp: { id: 'otp_request', indicator: 'Request for OTP or credentials', category: 'credential', reason: 'Genuine banks state that they never ask customers to share OTPs, PINs or passwords.' },
  urgency: { id: 'urgency', indicator: 'Urgency / pressure wording', category: 'urgency', reason: 'Pressure to act immediately reduces time to check whether the request is genuine.' },
  click_link: { id: 'click_link', indicator: 'Instruction to open a link', category: 'link', reason: 'Links in unsolicited messages should be checked before use.' },
  remote_access: { id: 'remote_access', indicator: 'Remote-access application mentioned', category: 'remote_access', reason: 'Remote-access apps let someone else see or control your device and are a recognised risk.' },
  payment_request: { id: 'payment_request', indicator: 'Payment request wording', category: 'payment', reason: 'An unexpected request to pay or transfer money needs independent verification.' },
  verification_payment: { id: 'verification_fee', indicator: 'Verification / processing fee request', category: 'payment', reason: 'Being asked to pay a small "verification" amount to keep or recover an account is a recognised pattern.' },
  impersonation: { id: 'impersonation', indicator: 'Impersonation-style wording', category: 'impersonation_or_pressure', reason: 'The sender presents as an official or support representative. This claim is not verified.' },
};

function assessUrl(url) {
  const reasons = [];
  let host = '';
  try { host = new URL(/^https?:\/\//i.test(url) ? url : 'http://' + url).hostname.toLowerCase(); } catch { return reasons; }
  if (/^http:\/\//i.test(url)) reasons.push('The link does not use HTTPS.');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) reasons.push('The link uses a raw IP address instead of a domain name.');
  if (host.includes('xn--')) reasons.push('The domain uses punycode, which can disguise look-alike characters.');
  if (SHORTENERS.includes(host)) reasons.push('The link uses a URL shortener, which hides the real destination.');
  if (RISKY_TLDS.some((t) => host.endsWith(t))) reasons.push('The domain ends in a top-level domain frequently seen in throwaway sites.');
  if ((host.match(/-/g) || []).length >= 2) reasons.push('The domain contains several hyphens.');
  if (host.split('.').length > 4) reasons.push('The domain has many subdomains.');
  const hits = BRAND_WORDS.filter((w) => host.includes(w));
  if (hits.length >= 2) reasons.push('The domain mixes banking-style words (' + hits.join(', ') + ') which may be imitating a real service. Its owner is not verified.');
  return reasons;
}

function analyse(evidenceList, entities) {
  const evById = new Map(evidenceList.map((e) => [e.id, e]));
  const findings = [];
  const add = (ev, rule, supporting, ent) => findings.push({
    rule_id: rule.id, indicator: rule.indicator, category: rule.category,
    supporting_evidence: supporting, reason: rule.reason,
    // Lets the UI tie a finding to the exact entity (graph node id = entity_key) that triggered it.
    entity_key: ent ? ent.entity_type + '|' + ent.normalized_value : null,
    evidence_id: ev.id, evidence_type: ev.evidence_type, evidence_source: ev.source_identifier || null,
    kind: 'observation',
  });

  for (const ent of entities) {
    const ev = evById.get(ent.evidence_id);
    if (!ev) continue;
    if (ent.entity_type === 'phrase' && PHRASE_RULES[ent.normalized_value]) {
      add(ev, PHRASE_RULES[ent.normalized_value], ent.entity_value, ent);
    }
    if (ent.entity_type === 'url') {
      const reasons = assessUrl(ent.entity_value);
      if (reasons.length) add(ev, { id: 'suspicious_url', indicator: 'Unusual or potentially misleading URL', category: 'link', reason: reasons.join(' ') + ' The site was not visited or scanned.' }, ent.entity_value, ent);
    }
    if (ent.entity_type === 'upi' && ev.evidence_type === 'upi') {
      add(ev, { id: 'upi_request', indicator: 'Payment request to a UPI identifier', category: 'payment', reason: 'A payment is being requested to this identifier. Its owner has not been verified with a trusted source.' }, ent.entity_value, ent);
    }
  }

  // De-duplicate identical (rule, evidence, supporting text)
  const seen = new Set();
  const unique = findings.filter((f) => { const k = f.rule_id + f.evidence_id + f.supporting_evidence; if (seen.has(k)) return false; seen.add(k); return true; });

  const categories = new Set(unique.map((f) => f.category));
  const strong = unique.some((f) => ['credential', 'remote_access'].includes(f.category) && f.rule_id !== 'verify_request');
  let level = 'insufficient_evidence';
  if (unique.length > 0) level = 'needs_verification';
  if (strong || categories.size >= 3) level = 'high_concern';

  const strongList = [...new Set(unique.filter((f) => ['credential', 'remote_access'].includes(f.category) && f.rule_id !== 'verify_request').map((f) => f.indicator))];
  const catList = [...categories].map((c) => c.replace(/_/g, ' '));
  let triggeredBy = 'no_indicators';
  let basis = 'No indicators matched the rule set. This does not mean the content is safe.';
  if (unique.length) {
    triggeredBy = 'some_indicators';
    basis = `${unique.length} indicator(s) of ${categories.size} type(s) were found (${catList.join(', ')}). High concern needs a credential/OTP or remote-access request, or 3 or more different indicator types.`;
  }
  if (strong) { triggeredBy = 'credential_or_remote_access'; basis = `High concern because the evidence contains: ${strongList.join('; ')} (a credential/OTP or remote-access request).`; }
  else if (categories.size >= 3) { triggeredBy = 'three_indicator_types'; basis = `High concern because ${categories.size} different indicator types were found (${catList.join(', ')}). The threshold is 3.`; }

  const label = { high_concern: 'High concern', needs_verification: 'Needs further verification', insufficient_evidence: 'Insufficient evidence' }[level];
  return {
    risk_level: level, risk_label: label, findings: unique,
    method: 'Rule-based indicator check. High concern = a credential/OTP or remote-access request, or three or more different indicator types. This is not a fraud probability.',
    indicator_types: [...categories],
    rating_basis: { triggered_by: triggeredBy, explanation: basis, indicator_type_count: categories.size, high_concern_threshold: 3, strong_indicators: strongList },
  };
}

module.exports = { analyse, assessUrl };
