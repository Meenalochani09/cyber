'use strict';
// Evidence extraction engine. Pure functions, regex based, no network access.
// Everything returned is an OBSERVATION found in the text, not proof of fraud.

const SUSPICIOUS_PHRASES = [
  { key: 'kyc_expiry', re: /\bkyc\b[^.!?\n]{0,40}\b(expire[sd]?|will expire|update|pending|incomplete|verification)\b/i, label: 'KYC expiry / update claim' },
  { key: 'account_blocked', re: /\b(account|a\/c|card)\b[^.!?\n]{0,40}\b(blocked|suspended|frozen|deactivated|closed)\b/i, label: 'Account blocking claim' },
  { key: 'verify_account', re: /\bverify (your )?(account|identity|details|kyc|pan|aadhaar)\b/i, label: 'Verify your account request' },
  { key: 'share_otp', re: /\b(share|send|tell|enter|provide|give)\b[^.!?\n]{0,30}\b(otp|one[- ]time password|pin|cvv|password|passcode)\b/i, label: 'OTP / credential request' },
  { key: 'urgency', re: /\b(urgent(ly)?|immediately|right now|within \d+\s*(hours?|hrs?|minutes?|mins?)|today only|last warning|act now|expires? today)\b/i, label: 'Urgency / pressure wording' },
  { key: 'click_link', re: /\b(click|tap|open|visit)\b[^.!?\n]{0,25}\b(link|url|below|here)\b/i, label: 'Click-the-link instruction' },
  { key: 'remote_access', re: /\b(anydesk|teamviewer|quick\s?support|ammyy|rustdesk|screen\s?share|remote access)\b/i, label: 'Remote-access application mention' },
  { key: 'payment_request', re: /\b(pay|send|transfer|deposit)\b[^.!?\n]{0,30}(rs\.?|inr|₹|\bamount\b|\bfee\b|\bcharges?\b)|(rs\.?|inr|₹)\s?\d[\d,]*/i, label: 'Payment request wording' },
  { key: 'verification_payment', re: /\b(verification|refundable|processing|registration|activation)\s+(fee|charge|payment|amount)\b/i, label: 'Verification / processing fee request' },
  { key: 'impersonation', re: /\b(bank (official|representative|manager|executive)|customer care|support team|rbi|reserve bank|relationship manager|official support)\b/i, label: 'Impersonation-style wording' },
];

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;
const UPI_RE = /[A-Za-z0-9._-]{2,}@[A-Za-z][A-Za-z0-9]{1,63}(?![A-Za-z0-9]|\.[A-Za-z])/g;
const PHONE_RE = /(?<![\w@.\/-])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?![\d@])|(?<![\w@.\/-])\+\d{1,3}[\s-]?\d{6,12}(?![\d@])/g;
const DATE_RES = [
  /\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g,
  /\b\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}(?:\s+\d{1,2}:\d{2}(?:\s?[ap]m)?)?\b/gi,
  /\b\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?,?\s+\d{4}(?:,?\s+\d{1,2}:\d{2}(?:\s?[ap]m)?)?\b/gi,
];
const NAME_RES = [
  { type: 'name', re: /\b(?:my name is|this is|i am|i'm)\s+((?:Mr\.?|Ms\.?|Mrs\.?|Dr\.?)?\s?[A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})/g, why: 'Name stated explicitly in the message' },
  { type: 'name', re: /\b((?:Mr|Ms|Mrs|Dr)\.?\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)?)/g, why: 'Titled name appears in the message' },
  { type: 'organisation', re: /\b((?:[A-Z][A-Za-z&]+\s){1,3}(?:Bank|Insurance|Finance|Payments))\b/g, why: 'Organisation name appears in the message' },
];

function trimUrl(u) { return u.replace(/[.,;:!?)\]}>]+$/, ''); }

function normalizePhone(raw) {
  const digits = raw.replace(/[^\d+]/g, '');
  if (digits.startsWith('+')) return digits;
  if (digits.length === 10) return '+91' + digits;
  if (digits.length === 12 && digits.startsWith('91')) return '+' + digits;
  return digits;
}

function domainOf(url) {
  try { return new URL(/^https?:\/\//i.test(url) ? url : 'http://' + url).hostname.toLowerCase(); }
  catch { return null; }
}

function normalizeUrl(url) {
  try {
    const u = new URL(/^https?:\/\//i.test(url) ? url : 'http://' + url);
    return (u.protocol + '//' + u.host + u.pathname.replace(/\/$/, '') + u.search).toLowerCase();
  } catch { return url.toLowerCase(); }
}

function extractFromEvidence(ev) {
  const text = [ev.original_text, ev.source_identifier].filter(Boolean).join('\n');
  const out = [];
  const seen = new Set();
  const push = (type, value, normalized, confidence, explanation, method = 'regex') => {
    const k = type + '|' + normalized;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ evidence_id: ev.id, entity_type: type, entity_value: value, normalized_value: normalized,
      extraction_method: method, confidence, explanation });
  };
  if (!text.trim()) return out;

  let masked = text; // blank out matched spans so later patterns do not re-match inside them
  const mask = (m) => { masked = masked.split(m).join(' '.repeat(m.length)); };

  for (const m of text.match(URL_RE) || []) {
    const url = trimUrl(m);
    push('url', url, normalizeUrl(url), 0.95, 'URL found in submitted text. It was not opened or visited.');
    const d = domainOf(url);
    if (d) push('domain', d, d, 0.95, 'Domain taken from the URL ' + url);
    mask(m);
  }
  for (const m of masked.match(EMAIL_RE) || []) { push('email', m, m.toLowerCase(), 0.95, 'Email address pattern found.'); mask(m); }
  const phraseText = masked; // URLs and emails blanked, so wording inside a link is not treated as message wording
  for (const m of masked.match(UPI_RE) || []) { push('upi', m, m.toLowerCase(), 0.8, 'UPI-style identifier (name@handle). Recipient identity is NOT verified.'); mask(m); }
  for (const m of masked.match(PHONE_RE) || []) { push('phone', m.trim(), normalizePhone(m), 0.85, 'Phone number pattern found.'); mask(m); }
  for (const re of DATE_RES) for (const m of masked.match(re) || []) { push('date', m.trim(), m.trim().toLowerCase(), 0.7, 'Date/time text present in the message.'); mask(m); }
  for (const p of SUSPICIOUS_PHRASES) {
    const m = phraseText.match(p.re);
    if (m) push('phrase', m[0].trim(), p.key, 0.6, p.label + '. This is a wording observation, not proof of fraud.');
  }
  for (const n of NAME_RES) {
    n.re.lastIndex = 0;
    let m;
    while ((m = n.re.exec(text))) {
      const v = m[1].trim();
      push(n.type, v, v.toLowerCase(), 0.5, n.why + '. Identity not verified.');
    }
  }
  return out;
}

// Parses a timestamp supplied by the user. Returns an ISO string, or null if unknown/invalid.
function parseTimestamp(value) {
  if (!value) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

module.exports = { extractFromEvidence, parseTimestamp, domainOf, SUSPICIOUS_PHRASES };
