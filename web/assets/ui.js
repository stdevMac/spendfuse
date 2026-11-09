// Shared helpers for the landing and the console. Every value from /api/* goes into the page through
// textContent or a validated attribute; nothing here writes markup from a string.

export const BASE58_TX = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;
export const ACCOUNT = /^(?=.{2,64}$)(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const YOCTO = 10n ** 24n;

export async function fetchJSON(path, { timeout = 8000 } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(path, { headers: { accept: 'application/json' }, signal: ctl.signal, cache: 'no-store' });
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

// a yocto string to "1.25" (2 to 4 decimals, trailing zeros trimmed to 2)
export function formatNear(yocto, { min = 2, max = 4 } = {}) {
  let v;
  try { v = BigInt(String(yocto ?? '0')); } catch { return '?'; }
  const neg = v < 0n;
  if (neg) v = -v;
  const whole = v / YOCTO;
  let frac = (v % YOCTO).toString().padStart(24, '0').slice(0, max);
  while (frac.length > min && frac.endsWith('0')) frac = frac.slice(0, -1);
  return `${neg ? '-' : ''}${whole.toLocaleString('en-US')}${frac ? '.' + frac : ''}`;
}

export const toNear = (yocto) => {
  try { return Number(BigInt(String(yocto ?? '0')) * 10000n / YOCTO) / 10000; } catch { return 0; }
};

// el('span', { class: 'chip', text: 'paid', attrs: { title: '...' } }, ...children)
export function el(tag, opts = {}, ...children) {
  const n = document.createElement(tag);
  if (opts.class) n.className = opts.class;
  if (opts.text != null) n.textContent = String(opts.text);
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) if (v != null && !/^on/i.test(k) && k !== 'style') n.setAttribute(k, String(v));
  for (const c of children) if (c != null) n.append(c);
  return n;
}

export const txUrl = (hash) => (BASE58_TX.test(String(hash)) ? `https://testnet.nearblocks.io/txns/${hash}` : null);
export const accountUrl = (id) => (ACCOUNT.test(String(id)) ? `https://testnet.nearblocks.io/address/${id}` : null);
export const shortHash = (h) => (String(h).length > 12 ? `${String(h).slice(0, 6)}…${String(h).slice(-3)}` : String(h));
export const shortAccount = (id, max = 30) => {
  const s = String(id ?? '');
  return s.length > max ? `${s.slice(0, 12)}…${s.slice(-(max - 13))}` : s;
};

export function relTime(ms, now = Date.now()) {
  const t = Number(ms);
  if (!Number.isFinite(t) || t <= 0) return '';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 60) return `${d}d ago`;
  return new Date(t).toISOString().slice(0, 10);
}

// a log entry's kind as the product's state word and chip tone
const KINDS = {
  paid: ['paid', 'ok'],
  approved: ['approved', 'ok'],
  blocked: ['blocked', 'stop'],
  rejected: ['rejected', 'stop'],
  transfer_failed: ['transfer failed', 'stop'],
  escalated: ['held', 'warn'],
  expired: ['expired', 'warn'],
  tripped: ['tripped', 'trip'],
  frozen: ['frozen', 'trip'],
  unfrozen: ['unfrozen', 'info'],
  policy_updated: ['policy updated', 'info'],
};
export function kindChip(kind) {
  const [word, tone] = KINDS[kind] ?? [String(kind ?? 'event').replace(/_/g, ' '), ''];
  return el('span', { class: `chip${tone ? ' chip--' + tone : ''}`, text: word });
}

// one incident row (hero window and app-frame)
export function incidentRow(e, now = Date.now()) {
  const reasons = Array.isArray(e.reasons) && e.reasons.length ? e.reasons.join(' · ') : (e.note || e.kind || '');
  const who = e.receiver_id || e.agent_id || e.by || '';
  const amount = e.amount && e.amount !== '0' ? `${formatNear(e.amount)} NEAR` : '';
  return el('li', { class: 'inc' },
    el('span', { class: 'inc__chip' }, kindChip(e.kind)),
    el('span', { class: 'inc__who', text: shortAccount(who, 34), attrs: { title: who } }),
    el('span', { class: 'inc__amt', text: amount }),
    el('span', { class: 'inc__why', text: String(reasons) }),
    el('span', { class: 'inc__when', text: relTime(e.at_ms, now) }),
  );
}

export function skeletonRows(n) {
  return Array.from({ length: n }, () => el('li', { class: 'inc inc--skel', attrs: { 'aria-hidden': 'true' } },
    el('span', { class: 'inc__chip' }), el('span', { class: 'inc__who' }), el('span', { class: 'inc__amt' }), el('span', { class: 'inc__why' }), el('span', { class: 'inc__when' })));
}

export function setBar(barEl, ratio) {
  const r = Math.max(0, Math.min(1, Number(ratio) || 0));
  const i = barEl.querySelector('i') || barEl.appendChild(document.createElement('i'));
  i.style.setProperty('--fill', String(r));
  barEl.toggleAttribute('data-full', r >= 1);
}

export async function copyText(btn, text) {
  try {
    await navigator.clipboard.writeText(text);
    btn.setAttribute('data-done', '');
    const label = btn.querySelector('.copy__label');
    const was = label?.textContent;
    if (label) label.textContent = 'Copied';
    setTimeout(() => { btn.removeAttribute('data-done'); if (label && was) label.textContent = was; }, 1500);
  } catch { /* clipboard blocked: the text stays selectable */ }
}
