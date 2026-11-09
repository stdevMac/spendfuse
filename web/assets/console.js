// Spendfuse console. Reads /api/state, follows /api/events, pages /api/activity, reads /api/runs and,
// on the local server with a session token, signs owner actions through POST /api/<action>.
// Every value from the API reaches the page through textContent or a validated attribute.

import {
  BASE58_TX, ACCOUNT, fetchJSON, formatNear, toNear, el, accountUrl, shortHash, shortAccount, relTime,
  kindChip, incidentRow, skeletonRows, setBar, copyText,
} from './ui.js';

const $ = (id) => document.getElementById(id);
const TOKEN_RE = /^[A-Za-z0-9_-]{20,128}$/;
const RUN_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const FEED_MAX = 300;
const SAFE_URL = (h) => (BASE58_TX.test(String(h)) ? `https://testnet.nearblocks.io/txns/${h}` : null);
const METHODS = { approve: 'approve', reject: 'reject', freeze: 'freeze_agent', unfreeze: 'unfreeze_agent', pause: 'pause', unpause: 'unpause' };
const VIEWS = ['overview', 'agents', 'approvals', 'incidents', 'policy', 'runs', 'keys'];
const wide = window.matchMedia('(min-width: 900px)');

const S = {
  token: null,
  state: null,
  feed: new Map(),
  feedCap: FEED_MAX,
  oldestSeq: null,
  olderDone: false,
  fresh: new Set(),
  filter: 'all',
  route: { view: 'overview', a: null, b: null },
  runs: null,
  runCache: new Map(),
  live: 'wait',
  fail: 0,
  retryAt: 0,
  lastError: '',
  overlay: null,
  lastFocus: null,
};

const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };
const svg = (paths, box = '0 0 16 16') => {
  const ns = 'http://www.w3.org/2000/svg';
  const s = document.createElementNS(ns, 'svg');
  s.setAttribute('viewBox', box);
  s.setAttribute('aria-hidden', 'true');
  for (const d of paths) { const p = document.createElementNS(ns, 'path'); p.setAttribute('d', d); s.append(p); }
  return s;
};
const near = (y) => `${formatNear(y)} NEAR`;
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const fmtInt = (v) => num(v).toLocaleString('en-US');
const chip = (text, tone) => el('span', { class: `chip${tone ? ' chip--' + tone : ''}`, text });
const acct = (id, max = 40) => {
  const href = accountUrl(id);
  if (!href) return el('span', { class: 'mono', text: shortAccount(id, max) });
  return el('a', { class: 'mono cx-acc', text: shortAccount(id, max), attrs: { href, target: '_blank', rel: 'noopener noreferrer', title: id } });
};
const txLink = (hash, text) => {
  const href = SAFE_URL(hash);
  if (!href) return null;
  return el('a', { class: 'cx-tx', text: text || shortHash(hash), attrs: { href, target: '_blank', rel: 'noopener noreferrer', title: hash } });
};
const timeEl = (ms, cls = '') => el('span', { class: cls, text: relTime(ms), attrs: { 'data-at': String(ms ?? ''), title: Number(ms) > 0 ? new Date(Number(ms)).toLocaleString() : null } });
const kv = (dl, rows) => {
  clear(dl);
  for (const [k, v] of rows) {
    if (v == null || v === '') continue;
    dl.append(el('dt', { text: k }), v instanceof Node ? el('dd', {}, v) : el('dd', { text: String(v) }));
  }
};
const copyBtn = (text, label) => {
  const b = el('button', { class: 'copy cx-icon-copy', attrs: { type: 'button', 'aria-label': label || 'Copy' } },
    (() => { const s = svg(['M10.5 5V3.5A1.5 1.5 0 0 0 9 2H3.5A1.5 1.5 0 0 0 2 3.5V9a1.5 1.5 0 0 0 1.5 1.5H5']); s.classList.add('copy__idle'); const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect'); for (const [k, v] of Object.entries({ x: 5, y: 5, width: 8.5, height: 8.5, rx: 1.5 })) r.setAttribute(k, v); s.prepend(r); return s; })(),
    (() => { const s = svg(['m3 8.5 3 3 7-7']); s.classList.add('copy__done'); return s; })());
  b.addEventListener('click', () => copyText(b, text));
  return b;
};
const bytes = (s) => new TextEncoder().encode(s).length;
const cleanReason = (s) => {
  let out = String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, '');
  while (bytes(out) > 256) out = out.slice(0, -1);
  return out;
};
const seqCmp = (a, b) => { try { const x = BigInt(a), y = BigInt(b); return x > y ? -1 : x < y ? 1 : 0; } catch { return 0; } };
const reasonText = (r) => (typeof r === 'string' ? r : r && typeof r === 'object' ? [r.source, r.code].filter(Boolean).join(':') : String(r));

// ---------------------------------------------------------------- token and API
function initToken() {
  let t = null;
  try {
    const u = new URL(location.href);
    const q = u.searchParams.get('token');
    if (q && TOKEN_RE.test(q)) { t = q; try { sessionStorage.setItem('spendfuse-token', q); } catch { /* private mode */ } }
    if (u.searchParams.has('token')) { u.searchParams.delete('token'); history.replaceState(null, '', u.pathname + (u.search || '') + u.hash); }
  } catch { /* bad URL */ }
  if (!t) { try { const s = sessionStorage.getItem('spendfuse-token'); if (s && TOKEN_RE.test(s)) t = s; } catch { /* blocked */ } }
  S.token = t;
}

async function post(action, body) {
  if (!S.token) return { ok: false, error: 'This console has no session token.' };
  let r;
  try {
    r = await fetch(`/api/${action}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-spendfuse-token': S.token }, body: JSON.stringify(body || {}) });
  } catch (e) { return { ok: false, error: `The server did not answer: ${e.message}` }; }
  const out = await r.json().catch(() => ({}));
  if (!r.ok && !out.error) out.error = `HTTP ${r.status}`;
  if (!r.ok) out.ok = false;
  return out;
}

const mode = () => S.state?.mode ?? { readonly: true, actions: false, allowed: [] };
const canDo = (a) => !!(S.token && mode().actions && Array.isArray(mode().allowed) && mode().allowed.includes(a));

// ---------------------------------------------------------------- feed
function addFeed(list, fresh = false) {
  if (!Array.isArray(list)) return;
  for (const e of list) {
    if (!e || e.seq == null) continue;
    const k = String(e.seq);
    if (fresh && !S.feed.has(k)) S.fresh.add(k);
    S.feed.set(k, e);
  }
  const keys = [...S.feed.keys()].sort(seqCmp);
  for (const k of keys.slice(S.feedCap)) S.feed.delete(k);
  const kept = keys.slice(0, S.feedCap);
  S.oldestSeq = kept.length ? kept[kept.length - 1] : null;
}
const feedList = () => [...S.feed.keys()].sort(seqCmp).map((k) => S.feed.get(k));
const FILTERS = {
  all: () => true,
  paid: (e) => e.kind === 'paid' || e.kind === 'approved',
  held: (e) => e.kind === 'escalated' || e.kind === 'expired',
  blocked: (e) => e.kind === 'blocked' || e.kind === 'rejected' || e.kind === 'transfer_failed',
  tripped: (e) => e.kind === 'tripped' || e.kind === 'frozen',
  owner: (e) => {
    const c = S.state?.config;
    return !!c && (e.by === c.owner_id || (Array.isArray(c.guardians) && c.guardians.includes(e.by)));
  },
};

function incRow(e, full) {
  const li = incidentRow(e);
  li.querySelector('.inc__when')?.setAttribute('data-at', String(e.at_ms ?? ''));
  if (full) {
    const bits = [`#${e.seq}`];
    if (e.block_height) bits.push(`block ${e.block_height}`);
    if (e.request_id) bits.push(`request ${e.request_id}`);
    if (e.agent_id && e.receiver_id) bits.push(`${e.agent_id} → ${e.receiver_id}`);
    if (e.by) bits.push(`by ${e.by}`);
    li.append(el('span', { class: 'inc__meta', text: bits.join(' · ') }));
  }
  if (S.fresh.has(String(e.seq))) li.classList.add('is-new');
  return li;
}

// ---------------------------------------------------------------- header, banners, badges
function renderHeader() {
  const st = S.state;
  if (!st) return;
  const vid = $('vault-id');
  vid.textContent = st.vaultId || 'vault';
  const href = accountUrl(st.vaultId);
  if (href) vid.setAttribute('href', href); else vid.removeAttribute('href');
  vid.setAttribute('title', `${st.vaultId} on nearblocks`);
  $('vault-copy').hidden = !st.vaultId;
  $('net-chip').textContent = st.network || 'testnet';
  const c = st.config;
  const ver = $('ver-chip');
  ver.hidden = !c?.version;
  if (c?.version) ver.textContent = `v${c.version}`;
  const bal = clear($('balance'));
  if (c?.balance != null) bal.append('Balance ', el('b', { text: near(c.balance) }));
  const sc = $('status-chip');
  if (c) {
    sc.hidden = false;
    sc.className = `chip cx-status ${c.paused ? 'chip--stop' : 'chip--ok'}`;
    sc.setAttribute('data-tone', c.paused ? 'stop' : 'ok');
    sc.textContent = c.paused ? 'paused' : 'accepting payments';
  }
  const m = mode();
  const mc = $('mode-chip');
  mc.hidden = false;
  mc.removeAttribute('title');
  if (m.readonly || !m.actions) { mc.className = 'chip cx-mode'; mc.textContent = 'read-only'; }
  else if (!S.token) { mc.className = 'chip chip--warn cx-mode'; mc.textContent = 'no session token'; }
  else { mc.className = 'chip chip--info cx-mode'; mc.textContent = `signing as ${m.role || 'owner'}`; mc.setAttribute('title', m.signer || ''); }

  const n = Array.isArray(st.pending) ? st.pending.length : 0;
  for (const b of document.querySelectorAll('[data-badge="approvals"]')) { b.hidden = n === 0; b.textContent = String(n); }
  const tripped = (st.agents || []).some((a) => a.status?.state === 'frozen');
  document.title = `${n ? `(${n}) ` : ''}${tripped ? 'Frozen agent · ' : ''}Spendfuse console`;

  kv($('menu-kv'), [
    ['Vault', acct(st.vaultId)],
    ['Network', `NEAR ${st.network || 'testnet'}`],
    ['Contract', c?.version ? `v${c.version}` : null],
    ['Balance', c?.balance != null ? near(c.balance) : null],
    ['Status', c ? (c.paused ? 'paused' : 'accepting payments') : null],
    ['Mode', m.actions ? (S.token ? `signing as ${m.signer || m.role}` : 'can sign, no session token') : 'read-only'],
  ]);
}

function setLive(state, text, title = '') {
  const l = $('live');
  S.live = state;
  l.setAttribute('data-state', state);
  l.textContent = text;
  l.setAttribute('title', title || text);
  l.setAttribute('aria-label', text);
}

function banner(tone, text, ...extra) {
  const b = el('div', { class: 'cx-banner', attrs: { 'data-tone': tone } }, el('p', { class: 'cx-banner__text' }, ...(Array.isArray(text) ? text : [text])));
  if (extra.length) b.append(el('div', { class: 'cx-banner__btns' }, ...extra));
  return b;
}
const roDismissed = () => { try { return sessionStorage.getItem('spendfuse-ro-dismissed') === '1'; } catch { return false; } };

function renderBanners() {
  const box = clear($('banners'));
  const st = S.state;
  if (S.fail > 0) {
    const secs = Math.max(0, Math.ceil((S.retryAt - Date.now()) / 1000));
    const btn = el('button', { class: 'btn btn--secondary btn--sm', text: 'Retry now', attrs: { type: 'button' } });
    btn.addEventListener('click', () => refresh());
    box.append(banner('stop', [`The vault did not answer (${S.lastError}). Retrying in `, el('span', { text: `${secs}s`, attrs: { 'data-retry': '' } }), '.'], btn));
  }
  if (!st) return;
  const c = st.config;
  if (c?.paused) {
    const by = feedList().find((e) => e.kind === 'paused')?.by;
    box.append(banner('stop', `The vault is paused${by ? ` by ${by}` : ''}${c.pause_reason ? `: ${c.pause_reason}` : ''}. Every payment is refused until the owner unpauses.`));
  }
  for (const a of st.agents || []) {
    if (a.status?.state !== 'frozen') continue;
    const link = el('a', { class: 'btn btn--secondary btn--sm', text: 'Open agent', attrs: { href: `#agents/${encodeURIComponent(a.agent_id)}` } });
    box.append(banner('trip', `${a.agent_id} is frozen${a.status.reason ? `: ${a.status.reason}` : ''}. It cannot pay until the owner unfreezes it.`, link));
  }
  const m = mode();
  if (m.actions && !S.token) {
    box.append(banner('warn', ['This console can sign, but it has no session token. Open the link printed by ', el('code', { text: 'npm run dashboard' }), '.']));
  } else if (!m.actions && !roDismissed()) {
    const x = el('button', { class: 'cx-x', attrs: { type: 'button', 'aria-label': 'Dismiss' } }, svg(['m5 5 10 10M15 5 5 15'], '0 0 20 20'));
    x.addEventListener('click', () => { try { sessionStorage.setItem('spendfuse-ro-dismissed', '1'); } catch { /* blocked */ } renderBanners(); });
    box.append(banner('info', ['Read-only view of the testnet vault. Actions run from the local console: ', el('code', { text: 'npm run dashboard' }), '.'], x));
  }
  const errs = Object.entries(st.errors || {});
  if (errs.length) box.append(banner('warn', `Some views did not load: ${errs.map(([k, v]) => `${k} (${String(v).slice(0, 120)})`).join('; ')}.`));
}

// ---------------------------------------------------------------- overview
function stat(k, v, s, tone) {
  return el('div', { class: 'cx-stat', attrs: { 'data-tone': tone } }, el('span', { class: 'cx-stat__k', text: k }), el('b', { class: 'cx-stat__v', text: v }), el('span', { class: 'cx-stat__s', text: s }));
}
function agentRow(a, { pick = false, current = false } = {}) {
  const p = a.policy || {};
  const frozen = a.status?.state === 'frozen';
  const limit = toNear(p.daily_limit);
  const ratio = limit > 0 ? toNear(a.spent_24h) / limit : 0;
  const bar = el('div', { class: 'bar', attrs: { 'aria-hidden': 'true' } }, el('i'));
  setBar(bar, ratio);
  bar.toggleAttribute('data-warn', ratio >= 0.8);
  return el('li', {}, el('a', { class: 'cx-arow', attrs: { href: `#agents/${encodeURIComponent(a.agent_id)}`, 'aria-current': pick && current ? 'true' : null } },
    el('span', { class: 'cx-arow__id', text: a.agent_id }, a.label ? el('span', { class: 'cx-arow__label', text: a.label }) : null),
    frozen ? chip('frozen', 'trip') : chip('active', 'ok'),
    el('span', { class: 'cx-arow__lim' }, bar, el('span', { text: ratio >= 1 ? `daily limit reached · ${formatNear(p.daily_limit)}` : `${formatNear(a.spent_24h)} / ${formatNear(p.daily_limit)} today` })),
  ));
}

// money actually moved: automatic + owner-approved, minus transfers that failed and rolled back
// (the contract counts a failed transfer in paid or approved and in failed)
function paidCount(s) { return Math.max(0, num(s.paid) + num(s.approved) - num(s.failed)); }

function spendText(a) {
  const p = a.policy || {};
  const limit = toNear(p.daily_limit);
  const used = toNear(a.spent_24h);
  if (limit > 0 && used >= limit) return `Daily limit reached · ${near(p.daily_limit)}. Further agent payments are blocked`;
  return `${formatNear(a.spent_24h)} of ${near(p.daily_limit)}`;
}

function renderOverviewSide(st) {
  const c = st.config;
  const vk = clear($('ov-vault'));
  if (c) kv(vk, [
    ['Balance', near(c.balance)],
    ['Available to agents', near(c.available)],
    ['Storage lock', near(c.storage_locked)],
    ['Reserved for held payments', c.reserved && c.reserved !== '0' ? near(c.reserved) : null],
    ['Canaries armed', fmtInt(c.canaries)],
    ['Guardians', fmtInt(Array.isArray(c.guardians) ? c.guardians.length : 0)],
  ]); else kv(vk, [['Config', 'did not load from the chain']]);
  const agents = Array.isArray(st.agents) ? st.agents : [];
  const a = agents[0];
  const pk = clear($('ov-policy'));
  $('ov-policy-who').textContent = a ? shortAccount(a.agent_id, 30) : '';
  if (!a) { kv(pk, [['Policy', 'no agent registered']]); return; }
  const p = a.policy || {};
  kv(pk, [
    ['Max per payment', near(p.max_per_payment)],
    ['Daily limit', near(p.daily_limit)],
    ['Approval threshold', p.approval_threshold != null ? near(p.approval_threshold) : 'none'],
    ['New payee limit', p.new_payee_limit != null ? near(p.new_payee_limit) : 'none'],
    ['Payments per hour', fmtInt(p.max_payments_per_hour)],
    ['Spent, last 24 hours', spendText(a)],
  ]);
}

function renderOverview() {
  const st = S.state;
  if (!st) return;
  const s = st.stats || {};
  const c = st.config || {};
  $('ov-sub').textContent = `${st.vaultId} on NEAR ${st.network || 'testnet'} · read from the chain ${new Date(st.fetchedAt || Date.now()).toLocaleTimeString()}`;
  const stats = clear($('ov-stats'));
  if (st.stats) {
    stats.append(
      stat('Paid', fmtInt(paidCount(s)), `${near(s.paid_total)} sent${num(s.failed) ? ` · ${fmtInt(s.failed)} failed, rolled back` : ''}`, 'ok'),
      stat('Held for the owner', fmtInt(s.escalated), `${fmtInt(s.approved)} approved · ${fmtInt(s.rejected)} rejected`, 'warn'),
      stat('Blocked', fmtInt(s.blocked), `${fmtInt(num(s.blocked_while_frozen) + num(s.blocked_while_paused))} while frozen or paused`, 'stop'),
      stat('Tripped', fmtInt(s.tripped), `${fmtInt(s.freezes)} freezes · ${fmtInt(c.canaries)} canaries`, 'trip'),
    );
  } else stats.append(el('p', { class: 'cx-empty', text: 'Stats did not load from the chain.' }));

  const pend = Array.isArray(st.pending) ? st.pending : [];
  const strip = clear($('ov-pending'));
  strip.hidden = pend.length === 0;
  if (pend.length) strip.append(
    el('span', { class: 'cx-strip__n', text: String(pend.length) }),
    el('span', { class: 'cx-strip__t', text: `${pend.length === 1 ? 'payment is' : 'payments are'} waiting for the owner. Each one expires 24 hours after it was held.` }),
    el('span', { class: 'cx-strip__go', text: 'Review' }),
  );

  const ag = clear($('ov-agents'));
  const agents = Array.isArray(st.agents) ? st.agents : [];
  if (!agents.length) ag.append(el('li', { class: 'cx-empty', text: st.agents ? 'No agents registered on this vault yet.' : 'Agents did not load from the chain.' }));
  for (const a of agents.slice(0, 6)) ag.append(agentRow(a));
  renderOverviewSide(st);

  const inc = clear($('ov-incidents'));
  const list = feedList().slice(0, 8);
  if (!list.length) inc.append(el('li', { class: 'win__msg', text: 'No events yet. Payments, blocks and owner actions appear here as the vault writes them.' }));
  for (const e of list) inc.append(incRow(e, false));
}

// ---------------------------------------------------------------- agents
function meter(k, used, cap, text) {
  const ratio = cap > 0 ? used / cap : 0;
  const bar = el('div', { class: 'bar', attrs: { role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': String(cap), 'aria-valuenow': String(used), 'aria-label': k } }, el('i'));
  setBar(bar, ratio);
  bar.toggleAttribute('data-warn', ratio >= 0.8);
  return el('div', { class: 'cx-meter' }, el('div', { class: 'cx-meter__top' }, el('span', { class: 'cx-meter__k', text: k }), el('span', { class: 'cx-meter__v', text })), bar);
}

function renderAgents() {
  const st = S.state;
  if (!st) return;
  const agents = Array.isArray(st.agents) ? st.agents : [];
  const wantId = S.route.a;
  const current = agents.find((a) => a.agent_id === wantId) || (wide.matches ? agents[0] : null);
  const list = clear($('ag-list'));
  if (!agents.length) list.append(el('li', { class: 'cx-empty', text: st.agents ? 'No agents registered on this vault yet.' : 'Agents did not load from the chain.' }));
  for (const a of agents) list.append(agentRow(a, { pick: true, current: a === current }));
  const split = $('ag-split');
  split.toggleAttribute('data-has-detail', !!(wantId && current));
  $('view-agents').toggleAttribute('data-detail', !!(wantId && current));
  const box = clear($('ag-detail'));
  if (!current) {
    if (wantId) box.append(el('p', { class: 'cx-empty cx-empty--card', text: `No agent ${wantId} on this vault.` }));
    return;
  }
  const a = current;
  const p = a.policy || {};
  const frozen = a.status?.state === 'frozen';
  const btns = el('div', { class: 'cx-dhead__btns' });
  if (frozen && canDo('unfreeze')) btns.append(actionBtn('Unfreeze', 'btn--primary', () => confirmAction('unfreeze', { agent_id: a.agent_id }, [['Agent', a.agent_id]], `lets ${a.agent_id} pay again inside its policy.`)));
  if (!frozen && canDo('freeze')) btns.append(actionBtn('Freeze agent', 'btn--danger', () => confirmAction('freeze', { agent_id: a.agent_id }, [['Agent', a.agent_id]], `stops every payment from ${a.agent_id} until the owner unfreezes it.`, { reason: 'Reason (optional, stored on chain)' })));
  box.append(
    el('div', { class: 'cx-back-row' }, el('a', { class: 'cx-textlink', text: '← All agents', attrs: { href: '#agents' } })),
    el('div', { class: 'cx-dhead' },
      el('div', {},
        el('div', { class: 'cx-dhead__id', text: a.agent_id }),
        el('div', { class: 'cx-dhead__sub' }, frozen ? chip('frozen', 'trip') : chip('active', 'ok'), a.label ? el('span', { text: a.label }) : null,
          a.created_at_ms ? el('span', {}, 'registered ', timeEl(a.created_at_ms)) : null, acct(a.agent_id, 24)),
        frozen ? el('p', { class: 'cx-dhead__why', text: `Frozen${a.status.by ? ` by ${a.status.by}` : ''}${a.status.reason ? `: ${a.status.reason}` : ''}` }) : null,
      ),
      btns.childElementCount ? btns : null,
    ),
  );
  const thr = num(p.auto_freeze_after_blocks) > 0 ? Math.min(25, num(p.auto_freeze_after_blocks)) : 25;
  const perHour = num(p.max_payments_per_hour);
  box.append(el('section', { class: 'cx-panel' },
    el('header', { class: 'cx-panel__head' }, el('h2', { text: 'Limits right now' }), el('span', { class: 'cx-count', text: 'rolling windows' })),
    el('div', { class: 'cx-meters' },
      meter('Spent, last 24 hours', toNear(a.spent_24h), toNear(p.daily_limit), spendText(a)),
      meter('Payments, last hour', num(a.payments_last_hour), perHour, `${a.payments_last_hour} of ${perHour}`),
      meter('Blocks, last hour', num(a.blocks_last_hour), thr, `${a.blocks_last_hour} of ${thr} before auto-freeze`),
    ),
  ));
  const k = a.counters || {};
  const counters = el('div', { class: 'cx-counters' });
  for (const [key, label] of [['paid', 'paid'], ['blocked', 'blocked'], ['escalated', 'held'], ['tripped', 'tripped'], ['approved', 'approved'], ['rejected', 'rejected'], ['expired', 'expired'], ['failed', 'failed'], ['blocked_while_frozen', 'while frozen'], ['reports', 'reports']]) {
    counters.append(el('div', { class: 'cx-counter' }, el('span', { class: 'cx-counter__v', text: fmtInt(k[key]) }), el('span', { class: 'cx-counter__k', text: label })));
  }
  box.append(el('section', { class: 'cx-panel' }, el('header', { class: 'cx-panel__head' }, el('h2', { text: 'Lifetime counters' }), el('span', { class: 'cx-count', text: `${near(a.total_spent)} spent · ${fmtInt(a.payee_count)} payees` })), counters));

  const allow = Array.isArray(p.allowlist) ? p.allowlist : [];
  const dl = el('dl', { class: 'cx-kv' });
  kv(dl, [
    ['Max per payment', near(p.max_per_payment)],
    ['Daily limit', near(p.daily_limit)],
    ['Approval threshold', p.approval_threshold != null ? `${near(p.approval_threshold)}, above it a human signs` : 'none'],
    ['New payee limit', p.new_payee_limit != null ? `${near(p.new_payee_limit)}, a first payment above it is held` : 'none'],
    ['Payments per hour', String(perHour)],
    ['Allowlist', p.allowlist_only
      ? (allow.length ? el('span', { class: 'cx-chips' }, ...allow.map((x) => acct(x, 32))) : 'allowlist only, empty')
      : el('span', { class: 'cx-allow' }, allow.length ? el('span', { class: 'cx-chips' }, ...allow.map((x) => acct(x, 32))) : null,
        el('span', { class: 'cx-dim', text: 'other payees allowed; new ones above the new-payee limit are held' }))],
    ['Auto-freeze', `after ${thr} blocks in an hour${num(p.auto_freeze_after_blocks) ? '' : ' (backstop)'}`],
    ['Expires', p.expires_at_ms ? el('span', {}, new Date(num(p.expires_at_ms)).toLocaleString(), ' · ', timeEl(p.expires_at_ms, 'cx-dim')) : 'never'],
    ['Reserved', a.reserved && a.reserved !== '0' ? near(a.reserved) : null],
    ['Held requests', Array.isArray(a.pending_ids) && a.pending_ids.length ? a.pending_ids.map((x) => `#${x}`).join(', ') : null],
  ]);
  box.append(el('section', { class: 'cx-panel' }, el('header', { class: 'cx-panel__head' }, el('h2', { text: 'Policy' }), el('span', { class: 'cx-count', text: 'enforced by the contract' })), dl));

  const mine = feedList().filter((e) => e.agent_id === a.agent_id).slice(0, 12);
  const ol = el('ol', { class: 'cx-inc' });
  if (!mine.length) ol.append(el('li', { class: 'win__msg', text: 'No events for this agent in the loaded activity.' }));
  for (const e of mine) ol.append(incRow(e, false));
  box.append(el('section', { class: 'cx-panel' }, el('header', { class: 'cx-panel__head' }, el('h2', { text: 'Recent events' }), el('a', { class: 'cx-textlink', text: 'All incidents', attrs: { href: '#incidents' } })), ol));
}

// ---------------------------------------------------------------- approvals
function actionBtn(text, cls, fn) {
  const b = el('button', { class: `btn ${cls}`, text, attrs: { type: 'button' } });
  b.addEventListener('click', fn);
  return b;
}
function countdown(ms) {
  const left = num(ms) - Date.now();
  if (left <= 0) return 'expired';
  const m = Math.floor(left / 60000);
  const h = Math.floor(m / 60);
  return h ? `${h}h ${String(m % 60).padStart(2, '0')}m left` : `${m}m ${String(Math.floor(left / 1000) % 60).padStart(2, '0')}s left`;
}

function renderApprovals() {
  const st = S.state;
  if (!st) return;
  const box = clear($('ap-list'));
  const pend = Array.isArray(st.pending) ? st.pending : null;
  if (!pend) { box.append(el('p', { class: 'cx-empty cx-empty--card', text: 'Pending payments did not load from the chain.' })); return; }
  if (!pend.length) {
    const done = feedList().filter((e) => e.kind === 'approved' || e.kind === 'rejected' || e.kind === 'expired').slice(0, 6);
    const ol = el('ol', { class: 'cx-inc' });
    for (const e of done) ol.append(incRow(e, false));
    if (!done.length) ol.append(el('li', { class: 'win__msg', text: 'No owner decisions in the loaded activity yet.' }));
    box.append(
      el('div', { class: 'cx-zero' },
        el('span', { class: 'cx-zero__icon', attrs: { 'aria-hidden': 'true' } }, svg(['M4 10.5 8 14.5 16 6'], '0 0 20 20')),
        el('div', {}, el('h2', { text: 'No payments waiting' }),
          el('p', { class: 'cx-dim', text: 'Requests over the approval threshold, to new payees or to reported receivers land here for 24 hours.' }))),
      el('section', { class: 'cx-panel cx-wide' }, el('header', { class: 'cx-panel__head' }, el('h2', { text: 'Recent decisions' }), el('a', { class: 'cx-textlink', text: 'All incidents', attrs: { href: '#incidents' } })), ol),
    );
    return;
  }
  for (const p of pend) {
    const reasons = (Array.isArray(p.reasons) ? p.reasons : []).map((r) => el('span', { class: 'cx-reason', text: reasonText(r) }));
    const btns = el('div', { class: 'cx-card__btns' });
    const rows = [['Request', `#${p.id}`], ['Agent', p.agent_id], ['To', p.receiver_id], ['Amount', near(p.amount)]];
    if (canDo('reject')) btns.append(actionBtn('Reject', 'btn--quiet', () => confirmAction('reject', { request_id: String(p.id) }, rows, `refuses request #${p.id}; nothing is paid.`, { reason: 'Reason (optional, stored on chain)' })));
    if (canDo('approve')) btns.append(actionBtn('Approve and pay', 'btn--primary', () => confirmAction('approve', { request_id: String(p.id) }, rows, `pays ${near(p.amount)} from the vault to ${p.receiver_id}.`)));
    box.append(el('article', { class: 'cx-card cx-card--warn' },
      el('div', { class: 'cx-card__top' }, chip('held for approval', 'warn'), el('span', { class: 'cx-chips' }, ...reasons)),
      el('div', { class: 'cx-card__amt', text: formatNear(p.amount) }, el('small', { text: 'NEAR' })),
      el('dl', { class: 'cx-card__flow' }, el('dt', { text: 'From' }), el('dd', {}, acct(p.agent_id)), el('dt', { text: 'To' }), el('dd', {}, acct(p.receiver_id)), el('dt', { text: 'Request' }), el('dd', { text: `#${p.id}` })),
      p.memo ? el('p', { class: 'cx-card__memo', text: p.memo }) : null,
      el('div', { class: 'cx-card__time' }, el('span', {}, 'held ', timeEl(p.created_at_ms)), el('b', { text: countdown(p.expires_at_ms), attrs: { 'data-exp': String(p.expires_at_ms) } })),
      btns.childElementCount ? btns : el('p', { class: 'cx-dim cx-field__hint', text: mode().actions ? 'Open the console link with a session token to sign.' : 'Approve or reject from the local console: npm run dashboard.' }),
    ));
  }
}

// ---------------------------------------------------------------- incidents
function renderIncidents() {
  const st = S.state;
  const ol = clear($('in-list'));
  for (const b of document.querySelectorAll('.cx-filter')) b.setAttribute('aria-pressed', String(b.dataset.filter === S.filter));
  const all = feedList();
  const list = all.filter(FILTERS[S.filter] || FILTERS.all);
  if (!st && !all.length) { for (const r of skeletonRows(6)) ol.append(r); return; }
  if (!list.length) ol.append(el('li', { class: 'win__msg', text: S.filter === 'all' ? 'No events yet. Payments, blocks and owner actions appear here as the vault writes them.' : 'No loaded events match this filter. Load older events to search further back.' }));
  for (const e of list) ol.append(incRow(e, true));
  const c = st?.config;
  $('in-sub').textContent = c?.activity_written != null
    ? `Showing ${all.length} of ${fmtInt(c.activity_written)} events; the vault keeps the last ${fmtInt(c.ring_capacity)}. Newest first.`
    : 'Every payment, block and owner action the vault wrote, newest first.';
  $('in-more').hidden = !(S.oldestSeq && S.oldestSeq !== '0' && all.length >= 10 && !S.olderDone);
}

async function loadOlder() {
  if (!S.oldestSeq) return;
  const btn = $('in-more');
  btn.disabled = true;
  btn.textContent = 'Loading...';
  try {
    const r = await fetchJSON(`/api/activity?before=${encodeURIComponent(S.oldestSeq)}&limit=50`);
    const before = S.feed.size;
    S.feedCap = Math.max(S.feedCap, S.feed.size + 50);
    addFeed(r.activity || []);
    if (S.feed.size === before) S.olderDone = true;
    renderIncidents();
  } catch (e) {
    toast(`Could not load older events: ${e.message}`, 'stop');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Load older';
  }
}

// ---------------------------------------------------------------- policy
function renderPolicy() {
  const st = S.state;
  if (!st) return;
  const c = st.config;
  const acts = clear($('po-actions'));
  if (c && !c.paused && canDo('pause')) acts.append(actionBtn('Pause the vault', 'btn--danger', () => confirmAction('pause', {}, [['Vault', st.vaultId]], 'refuses every payment from every agent until the owner unpauses.', { reason: 'Reason (optional, stored on chain)' })));
  if (c && c.paused && canDo('unpause')) acts.append(actionBtn('Unpause', 'btn--primary', () => confirmAction('unpause', {}, [['Vault', st.vaultId]], 'lets agents pay again inside their policies.')));
  const guardians = Array.isArray(c?.guardians) ? c.guardians : [];
  kv($('po-kv'), c ? [
    ['Vault', acct(st.vaultId)],
    ['Owner', acct(c.owner_id)],
    ['Pending owner', c.pending_owner ? acct(c.pending_owner) : null],
    ['Guardians', guardians.length ? el('span', { class: 'cx-chips' }, ...guardians.map((g) => acct(g, 32))) : 'none'],
    ['Status', c.paused ? `paused${c.pause_reason ? `: ${c.pause_reason}` : ''}` : 'accepting payments'],
    ['Contract', c.version ? `v${c.version}` : null],
    ['Balance', near(c.balance)],
    ['Storage lock', near(c.storage_locked)],
    ['Reserved for held payments', near(c.reserved)],
    ['Available to agents', near(c.available)],
    ['Canaries armed', fmtInt(c.canaries)],
    ['Blocklist', `${fmtInt(c.blocklist)} entries · ${fmtInt(c.open_reports)} open reports`],
    ['Activity', `${fmtInt(c.activity_written)} events written · last ${fmtInt(c.ring_capacity)} kept`],
  ] : [['Config', 'did not load from the chain']]);
  const bl = Array.isArray(st.blocklist) ? st.blocklist : [];
  $('po-bl-count').textContent = st.blocklist ? `${bl.length} ${bl.length === 1 ? 'entry' : 'entries'}` : '';
  const ul = clear($('po-blocklist'));
  if (!bl.length) ul.append(el('li', { class: 'cx-empty', text: st.blocklist ? 'No accounts reported or blocked.' : 'The blocklist did not load from the chain.' }));
  for (const b of bl) {
    ul.append(el('li', {},
      el('div', { class: 'cx-rows__top' }, acct(b.account_id), b.status === 'confirmed' ? chip('blocked', 'stop') : chip('reported, payments held', 'warn'), el('span', { class: 'cx-dim', text: `${b.reports} report${b.reports === 1 ? '' : 's'}` }), timeEl(b.at_ms, 'cx-dim')),
      b.reason ? el('div', { text: b.reason }) : null,
      el('div', { class: 'cx-rows__sub', text: [b.evidence ? `evidence: ${b.evidence}` : '', `reported by ${b.reporter}`, b.confirmed_by ? `confirmed by ${b.confirmed_by}` : ''].filter(Boolean).join(' · ') }),
    ));
  }
}

// ---------------------------------------------------------------- keys
function midEllipsis(s, n = 22) { const t = String(s); return t.length > n ? `${t.slice(0, 14)}…${t.slice(-6)}` : t; }
function renderKeys() {
  const st = S.state;
  if (!st) return;
  const box = clear($('keys-list'));
  const proofs = Array.isArray(st.keys) ? st.keys : [];
  if (!proofs.length) { box.append(el('p', { class: 'cx-empty cx-empty--card', text: 'No agent accounts to inspect yet.' })); return; }
  for (const pr of proofs) {
    const keys = Array.isArray(pr.keys) ? pr.keys : [];
    const head = pr.error ? chip('could not read keys', 'warn') : pr.fullAccess > 0 ? chip('full access present', 'stop') : pr.fcOnly ? chip('vault-only key', 'ok') : chip('function-call keys', 'info');
    const card = el('article', { class: 'cx-card' }, el('div', { class: 'cx-card__top' }, acct(pr.accountId), head));
    if (pr.error) card.append(el('p', { class: 'cx-dim', text: String(pr.error).slice(0, 200) }));
    if (pr.fullAccess > 0) card.append(el('p', { class: 'cx-warn', text: "Full-access key on this agent account: whoever holds it can spend this account's own balance and add keys. Vault funds still move only through request_payment and the policy." }));
    else if (pr.fcOnly) card.append(el('p', { class: 'cx-dim cx-field__hint', text: 'Only function-call keys for the vault: this account can ask the vault to pay, and nothing else.' }));
    if (!keys.length && !pr.error) card.append(el('p', { class: 'cx-dim', text: 'No access keys on this account.' }));
    for (const k of keys) {
      const what = k.fullAccess
        ? el('span', { class: 'cx-key__what' }, chip('full access', 'stop'))
        : el('span', { class: 'cx-key__what' }, 'function call: ', el('code', { text: k.receiverId || '?' }), ` · ${Array.isArray(k.methodNames) && k.methodNames.length ? k.methodNames.join(', ') : 'any method'}${k.allowance ? ` · allowance ${near(k.allowance)}` : ''}`);
      card.append(el('div', { class: 'cx-key' }, el('div', { class: 'cx-key__pk' }, el('code', { text: midEllipsis(k.publicKey), attrs: { title: k.publicKey } }), copyBtn(String(k.publicKey), 'Copy the public key')), what));
    }
    box.append(card);
  }
}

// ---------------------------------------------------------------- runs
const KIND = {
  legit: 'normal', 'over-threshold': 'normal',
  injection: 'attack', salami: 'attack', canary: 'attack', 'stolen-key': 'attack', 'bypass-cap': 'attack',
  'missing-receiver': 'mistake',
};
const KIND_WORD = { normal: 'normal payment', attack: 'attack', mistake: 'mistake' };
const RESULTS = [
  ['tripped', 'tripped, frozen', 'trip'], ['auto_frozen', 'auto-frozen', 'trip'], ['approved_paid', 'held, then approved', 'ok'],
  ['rejected_by_human', 'held, then rejected', 'warn'], ['protocol_rejected', 'rejected by protocol', 'stop'], ['chain_blocked', 'blocked on chain', 'stop'],
  ['rolled_back', 'refused, rolled back', 'stop'], ['paid', 'paid', 'ok'], ['escalated', 'held for approval', 'warn'], ['refused', 'refused', 'stop'],
];
const OUTCOME_WORD = Object.fromEntries(RESULTS.map(([k, w, t]) => [k, [w, t]]));
function resultChip(outcomes) {
  const set = new Set(outcomes);
  const hit = RESULTS.find(([k]) => set.has(k));
  if (hit) return chip(hit[1], hit[2]);
  return chip(outcomes[0] ? String(outcomes[0]).replace(/_/g, ' ') : 'no outcome');
}
function outcomeCounts(outcomes) {
  const m = new Map();
  for (const o of outcomes) m.set(o, (m.get(o) || 0) + 1);
  return [...m].map(([k, n]) => el('span', { class: 'cx-reason', text: `${String(k).replace(/_/g, ' ')}${n > 1 ? ` ×${n}` : ''}` }));
}
function injectedText(sc) {
  const tr = Array.isArray(sc.transcript) ? sc.transcript : [];
  const attack = KIND[sc.id] === 'attack';
  const doc = tr.find((t) => t && t.kind === 'tool_result' && /^UNTRUSTED DOCUMENT/.test(String(t.text)));
  if (doc) {
    const body = String(doc.text).split('\n').slice(1).filter((l) => !/^-{3,}$/.test(l.trim())).join('\n').trim();
    return [attack ? 'Injected text the agent read' : 'Document the agent read', body];
  }
  const att = tr.filter((t) => t && t.kind === 'attacker').map((t) => String(t.text));
  if (att.length) return ['What the attacker tried', att.join('\n')];
  return null;
}
function txItems(txs, max = Infinity) {
  const ul = el('ul', { class: 'cx-txs' });
  const list = Array.isArray(txs) ? txs : [];
  for (const t of list.slice(0, max)) {
    const link = !t.simulated ? txLink(t.hash) : null;
    ul.append(el('li', { attrs: { 'data-verified': link ? 'true' : null } }, el('span', { text: `${t.label || t.method || 'tx'}${t.ok === false ? ' (failed)' : ''}`, attrs: { title: `${t.method || ''} by ${t.actor || '?'}` } }),
      link || (t.simulated ? chip('simulated') : chip('no valid hash'))));
  }
  if (list.length > max) ul.append(el('li', {}, el('span', { text: `${list.length - max} more in the full detail` })));
  return list.length ? ul : null;
}
const rawBlock = (obj, label = 'Raw JSON', open = false) => {
  const d = el('details', { class: 'cx-raw' }, el('summary', { text: label }), el('pre', { text: JSON.stringify(obj, null, 2) }));
  if (open) d.open = true;
  return d;
};

// clamped text with a toggle; the clamp sits on an inner span so a line is never cut through the middle
function expandable(cls, text) {
  const t = el('span', { class: 'cx-clamp', text });
  const b = el('button', { class: 'cx-more', text: 'Show all', attrs: { type: 'button', 'aria-expanded': 'false' } });
  b.addEventListener('click', () => { const on = t.toggleAttribute('data-open'); b.setAttribute('aria-expanded', String(on)); b.textContent = on ? 'Show less' : 'Show all'; });
  const p = el('p', { class: cls }, t, b);
  requestAnimationFrame(() => { if (t.scrollHeight <= t.clientHeight + 1) b.hidden = true; });
  return p;
}

function scenarioCard(runId, sc) {
  const kind = KIND[sc.id] || 'other';
  const outcomes = Array.isArray(sc.outcomes) ? sc.outcomes.map(String) : [];
  const inj = injectedText(sc);
  const href = `#runs/${encodeURIComponent(runId)}/${encodeURIComponent(String(sc.n))}`;
  return el('article', { class: 'cx-sc', attrs: { 'data-kind': kind } },
    el('div', { class: 'cx-sc__top' }, el('span', { class: 'cx-sc__n', text: String(sc.n ?? '?') }), el('span', { class: 'cx-sc__kind', text: KIND_WORD[kind] || String(sc.id || 'scenario'), attrs: { 'data-kind': kind } }),
      el('span', { class: 'cx-pass', text: sc.pass === true ? 'pass' : sc.pass === false ? 'fail' : 'no verdict', attrs: { 'data-pass': String(sc.pass) } })),
    el('h3', { class: 'cx-sc__title' }, el('a', { text: sc.title || sc.id || 'Scenario', attrs: { href } })),
    el('div', { class: 'cx-sc__res' }, resultChip(outcomes), sc.frozenAfter ? el('span', { class: 'cx-dim', text: 'agent left frozen' }) : null),
    expandable('cx-sc__exp', sc.expected || '—'),
    txItems(sc.txs, 5),
    inj ? el('blockquote', { class: 'cx-quote' }, el('span', { class: 'cx-quote__k', text: inj[0] }), el('span', { class: 'cx-quote__t', text: inj[1] })) : null,
    el('div', { class: 'cx-sc__foot' }, rawBlock(sc), el('a', { class: 'cx-textlink', text: 'Full detail', attrs: { href } })),
  );
}

function runLabel(r) {
  const when = r.startedAt || r.started_at || (r.mtimeMs ? new Date(r.mtimeMs).toISOString() : '');
  const d = when ? new Date(when) : null;
  const ts = d && !Number.isNaN(d.getTime()) ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
  if (r.invalid) return `${r.id} (not valid JSON)`;
  if (typeof r.passed === 'number' && typeof r.total === 'number') return `${r.dryRun ? 'Dry run' : 'Live testnet'} · ${r.passed} of ${r.total} passed · ${ts}`;
  if (/^drill-/.test(r.id) || typeof r.pass === 'boolean') return `${r.dryRun ? 'Dry drill' : 'Canary drill'} · ${r.pass ? 'pass' : 'fail'} · ${ts}`;
  return `${String(r.title || r.name || r.scenario || r.id).slice(0, 60)} · ${ts}`;
}

async function loadRuns(force = false) {
  if (S.runs && !force) return S.runs;
  try {
    const r = await fetchJSON('/api/runs');
    S.runs = Array.isArray(r.runs) ? r.runs.filter((x) => x && RUN_ID_RE.test(String(x.id))) : [];
  } catch (e) {
    S.runs = null;
    throw e;
  }
  const sel = clear($('run-pick'));
  const live = S.runs.filter((r) => r.dryRun === false);
  const dry = S.runs.filter((r) => r.dryRun !== false);
  const group = (label, list) => list.length && sel.append(el('optgroup', { attrs: { label } }, ...list.map((r) => el('option', { text: runLabel(r), attrs: { value: r.id } }))));
  group('Live testnet', live);
  group('Dry runs and other files', dry);
  sel.disabled = !S.runs.length;
  return S.runs;
}
async function getRun(id) {
  if (S.runCache.has(id)) return S.runCache.get(id);
  const r = await fetchJSON(`/api/runs/${encodeURIComponent(id)}`, { timeout: 15000 });
  S.runCache.set(id, r.run);
  return r.run;
}

let runSeq = 0;
async function renderRuns() {
  const body = $('run-body');
  const my = ++runSeq;
  let runs;
  try { runs = await loadRuns(); } catch (e) {
    clear(body).append(el('p', { class: 'cx-empty cx-empty--card', text: `Could not list runs: ${e.message}` }));
    return;
  }
  if (my !== runSeq) return;
  if (!runs.length) { clear(body).append(el('p', { class: 'cx-empty cx-empty--card', text: 'No recorded runs on this server. Run npm run demo to record one.' })); return; }
  // no run in the URL: open the newest live run, so the default view is on-chain proof, not placeholders
  const id = runs.some((r) => r.id === S.route.a) ? S.route.a : (runs.find((r) => r.dryRun === false) || runs[0]).id;
  $('run-pick').value = id;
  if (!S.runCache.has(id)) clear(body).append(el('p', { class: 'cx-empty', text: 'Reading the run...' }));
  let run;
  try { run = await getRun(id); } catch (e) {
    if (my === runSeq) clear(body).append(el('p', { class: 'cx-empty cx-empty--card', text: `Could not read ${id}: ${e.message}` }));
    return;
  }
  if (my !== runSeq) return;
  clear(body).append(...runView(id, run));
  if (S.route.b != null && Array.isArray(run?.scenarios)) {
    const sc = run.scenarios.find((s) => String(s.n) === S.route.b);
    if (sc) openDrawer(id, sc); else closeDrawer(false);
  } else if (S.overlay === 'drawer') closeDrawer(false);
}

function runView(id, run) {
  if (run && Array.isArray(run.scenarios)) {
    const ok = run.scenarios.filter((s) => s.pass === true).length;
    const total = typeof run.total === 'number' ? run.total : run.scenarios.length;
    const passed = typeof run.passed === 'number' ? run.passed : ok;
    const item = (k, v) => (v ? el('div', { class: 'cx-runbar__kv' }, el('span', { text: k }), el('span', { text: v })) : null);
    const started = run.startedAt ? new Date(run.startedAt) : null;
    const dur = started && run.finishedAt ? Math.round((new Date(run.finishedAt) - started) / 1000) : null;
    const bar = el('div', { class: 'cx-runbar' },
      el('div', { class: 'cx-runbar__score' }, el('b', { text: `${passed}/${total}` }), el('span', { text: 'scenarios passed' })),
      item('Started', started && !Number.isNaN(started.getTime()) ? `${started.toLocaleString()}${dur != null ? ` · ${dur}s` : ''}` : null),
      item('Vault', run.vault), item('Agent', run.agent), item('Agent driver', run.llm ? (String(run.llm) === 'scripted' ? 'scripted (not a live LLM)' : String(run.llm)) : null),
      el('div', { class: 'cx-runbar__chips' }, run.dryRun ? chip('dry run, simulated', 'warn') : chip('live on testnet', 'info'), passed === total ? chip('all passed', 'ok') : chip(`${total - passed} failed`, 'stop')),
    );
    const grid = el('div', { class: 'cx-runs' });
    for (const sc of [...run.scenarios].sort((a, b) => num(a.n) - num(b.n))) grid.append(scenarioCard(id, sc));
    const note = run.dryRun ? el('p', { class: 'cx-dim cx-field__hint', text: 'Dry run: no transaction was sent, every hash in it is a placeholder.' }) : null;
    return [bar, note, grid, rawBlock(run, 'Raw JSON for the whole run')].filter(Boolean);
  }
  if (run && Array.isArray(run.steps)) {
    const steps = el('ul', { class: 'cx-steps' });
    for (const s of run.steps) steps.append(el('li', {}, s.ok ? chip('ok', 'ok') : chip('failed', 'stop'), el('span', { text: s.step || s.name || 'step' }), el('span', { text: s.detail || '' })));
    return [el('div', { class: 'cx-runs' }, el('article', { class: 'cx-sc cx-sc--drill' },
      el('div', { class: 'cx-sc__top' }, el('span', { class: 'cx-sc__kind', text: run.dryRun ? 'canary drill, dry run' : 'canary drill', attrs: { 'data-kind': 'attack' } }),
        el('span', { class: 'cx-pass', text: run.pass ? 'pass' : 'fail', attrs: { 'data-pass': String(!!run.pass) } })),
      el('h3', { class: 'cx-sc__title', text: 'Plant a canary, leak it, watch the vault trip' }),
      steps, txItems(run.txs), rawBlock(run)))];
  }
  return [el('article', { class: 'cx-sc' }, el('h3', { class: 'cx-sc__title', text: String(run?.title || run?.name || id) }), el('p', { class: 'cx-dim', text: 'This file is not a suite run or a drill; here it is as recorded.' }), rawBlock(run, 'Raw JSON', true))];
}

// ---------------------------------------------------------------- drawer (scenario detail)
function dsec(title, ...kids) { return el('section', { class: 'cx-dsec' }, el('h3', { text: title }), ...kids); }
function openDrawer(runId, sc) {
  const outcomes = Array.isArray(sc.outcomes) ? sc.outcomes.map(String) : [];
  $('drawer-h').textContent = `${sc.n}. ${sc.title || sc.id}`;
  const body = clear($('drawer-body'));
  body.append(dsec('Result', el('div', { class: 'cx-chips' },
    el('span', { class: 'cx-pass', text: sc.pass ? 'pass' : 'fail', attrs: { 'data-pass': String(!!sc.pass) } }), resultChip(outcomes), ...outcomeCounts(outcomes),
    sc.frozenAfter ? chip('agent frozen after', 'trip') : chip('agent active after')),
  sc.verdict?.summary ? el('p', { text: sc.verdict.summary }) : null));
  body.append(dsec('Expected', el('p', { text: sc.expected || '—' })));
  if (sc.why) body.append(dsec('Why it passed or failed', el('p', { class: 'mono', text: sc.why })));
  const inj = injectedText(sc);
  if (inj) body.append(dsec(inj[0], el('blockquote', { class: 'cx-quote', text: inj[1] })));
  const txs = Array.isArray(sc.txs) ? sc.txs : [];
  if (txs.length) {
    const tb = el('tbody');
    for (const t of txs) {
      const link = !t.simulated ? txLink(t.hash, shortHash(t.hash)) : null;
      tb.append(el('tr', {}, el('td', { text: t.label || '', attrs: { 'data-k': 'step' } }), el('td', { class: 'mono', text: t.method || '', attrs: { 'data-k': 'method' } }),
        el('td', { class: 'mono', text: shortAccount(t.actor || '', 30), attrs: { 'data-k': 'by', title: t.actor } }),
        el('td', { attrs: { 'data-k': 'tx' } }, link || (t.simulated ? chip('simulated') : chip('no valid hash')), t.ok === false ? chip('failed', 'stop') : null)));
    }
    body.append(dsec(`Transactions (${txs.length})`, el('table', { class: 'cx-table' }, el('thead', {}, el('tr', {}, ...['Step', 'Method', 'Signer', 'Transaction'].map((h) => el('th', { text: h })))), tb)));
  }
  const aps = Array.isArray(sc.approvals) ? sc.approvals : [];
  if (aps.length) {
    body.append(dsec(`Held for approval (${aps.length})`, ...aps.map((a) => el('div', { class: 'cx-card' },
      el('div', { class: 'cx-card__top' }, el('span', { class: 'mono', text: `#${a.request_id ?? '?'} · ${a.amount_near ?? '?'} NEAR → ${a.receiver_id ?? '?'}` }), el('span', { class: 'cx-dim', text: a.where || '' })),
      a.memo ? el('p', { class: 'cx-card__memo', text: a.memo }) : null,
      el('ul', { class: 'cx-steps' }, ...(Array.isArray(a.reasons) ? a.reasons : []).map((r) => el('li', {}, el('span', { class: 'cx-reason', text: reasonText(r) }), el('span', { text: r?.detail || '' }))))))));
  }
  const turns = Array.isArray(sc.turns) ? sc.turns : [];
  if (turns.length) body.append(dsec('Agent turns', el('p', { text: `${turns.length} turn${turns.length === 1 ? '' : 's'} · ${[...new Set(turns.map((t) => t.kind))].join(', ')} · ${turns.every((t) => t.verified) ? 'tx hashes verified on chain' : 'not all tx hashes verified'}` })));
  const tr = Array.isArray(sc.transcript) ? sc.transcript : [];
  if (tr.length) {
    const ol = el('ol', { class: 'cx-transcript' });
    for (const t of tr) ol.append(el('li', { attrs: { 'data-kind': String(t.kind || '') } }, el('span', { text: String(t.kind || '').replace(/_/g, ' ') }), el('div', { text: String(t.text ?? '') })));
    body.append(dsec(`Transcript (${tr.length})`, ol));
  }
  body.append(rawBlock(sc));
  showOverlay('drawer');
  body.scrollTop = 0;
}
function closeDrawer(nav = true) {
  if (S.overlay === 'drawer') hideOverlay();
  if (nav && S.route.view === 'runs' && S.route.b != null) location.hash = `#runs/${encodeURIComponent(S.route.a || '')}`;
}

// ---------------------------------------------------------------- overlays (menu, drawer) and focus
const OVERLAYS = { menu: 'menu-sheet', drawer: 'drawer', confirm: 'confirm' };
function showOverlay(name) {
  if (S.overlay && S.overlay !== name) hideOverlay();
  const was = S.overlay;
  S.overlay = name;
  if (!was) S.lastFocus = document.activeElement;
  const n = $(OVERLAYS[name]);
  n.hidden = false;
  $('scrim').hidden = name === 'confirm';
  document.documentElement.classList.add('cx-locked');
  if (name === 'menu') $('menu-btn').setAttribute('aria-expanded', 'true');
  const f = name === 'confirm' ? ($('confirm-reason-wrap').hidden ? $('confirm-cancel') : $('confirm-reason')) : n.querySelector('[data-close]:not([hidden])');
  requestAnimationFrame(() => f?.focus());
}
function hideOverlay() {
  if (!S.overlay) return;
  $(OVERLAYS[S.overlay]).hidden = true;
  if (S.overlay === 'menu') $('menu-btn').setAttribute('aria-expanded', 'false');
  S.overlay = null;
  $('scrim').hidden = true;
  document.documentElement.classList.remove('cx-locked');
  const f = S.lastFocus;
  S.lastFocus = null;
  if (f && document.contains(f)) f.focus();
}
function trapFocus(e) {
  if (e.key !== 'Tab' || !S.overlay) return;
  const root = $(OVERLAYS[S.overlay]);
  const items = [...root.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select, summary, [tabindex]:not([tabindex="-1"])')].filter((x) => x.offsetParent !== null);
  if (!items.length) return;
  const first = items[0], last = items[items.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  else if (!root.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
}

// ---------------------------------------------------------------- confirm sheet
let pending = null;
function confirmAction(action, body, rows, effect, { reason } = {}) {
  if (!canDo(action)) return;
  const m = mode();
  pending = { action, body, reason: !!reason, sending: false };
  $('confirm-h').textContent = '';
  $('confirm-h').append('Sign ', el('code', { text: METHODS[action] || action }), '?');
  const p = clear($('confirm-p'));
  p.append(`Signs a transaction on NEAR ${S.state?.network || 'testnet'} as `, el('b', { text: m.signer || m.role || 'the owner' }), `: it ${effect}`);
  kv($('confirm-kv'), [['Contract', S.state?.vaultId], ['Method', METHODS[action] || action], ...rows]);
  $('confirm-reason-wrap').hidden = !reason;
  if (reason) { $('confirm-reason-k').textContent = reason; $('confirm-reason').value = ''; updateHint(); }
  $('confirm-err').hidden = true;
  const ok = $('confirm-ok');
  ok.disabled = false;
  ok.textContent = 'Sign and send';
  ok.className = `btn ${action === 'freeze' || action === 'pause' || action === 'reject' ? 'btn--danger' : 'btn--primary'}`;
  $('confirm-cancel').disabled = false;
  showOverlay('confirm');
}
function updateHint() {
  const inp = $('confirm-reason');
  const v = cleanReason(inp.value);
  if (v !== inp.value) inp.value = v;
  $('confirm-reason-hint').textContent = `Plain text, stored on chain. ${bytes(v)} of 256 bytes.`;
}
function cancelConfirm() { if (pending?.sending) return; pending = null; hideOverlay(); }
async function submitConfirm(e) {
  e.preventDefault();
  if (!pending || pending.sending) return;
  const { action } = pending;
  const body = { ...pending.body };
  if (pending.reason) body.reason = cleanReason($('confirm-reason').value).trim();
  pending.sending = true;
  const ok = $('confirm-ok');
  ok.disabled = true;
  ok.textContent = 'Signing...';
  $('confirm-cancel').disabled = true;
  $('confirm-err').hidden = true;
  const out = await post(action, body);
  pending.sending = false;
  if (out && out.ok) {
    pending = null;
    hideOverlay();
    toast(`${METHODS[action] || action} signed and sent.`, 'ok', out.hash);
    S.runs = S.runs; // runs are unaffected
    scheduleRefresh(300);
    return;
  }
  const err = $('confirm-err');
  err.hidden = false;
  err.textContent = `Not sent: ${String(out?.error || 'unknown error').slice(0, 300)}`;
  if (out?.hash && SAFE_URL(out.hash)) err.append(' ', txLink(out.hash, 'see the transaction'));
  ok.disabled = false;
  ok.textContent = 'Try again';
  $('confirm-cancel').disabled = false;
}

// ---------------------------------------------------------------- toasts
function toast(text, tone = 'ok', hash = null) {
  const x = el('button', { class: 'cx-x', attrs: { type: 'button', 'aria-label': 'Dismiss' } }, svg(['m5 5 10 10M15 5 5 15'], '0 0 20 20'));
  const t = el('div', { class: 'cx-toast', attrs: { 'data-tone': tone, role: tone === 'stop' ? 'alert' : 'status' } },
    el('div', { class: 'cx-toast__text' }, el('span', { text }), hash && SAFE_URL(hash) ? el('br') : null, hash ? txLink(hash, `${shortHash(hash)} on nearblocks`) : null), x);
  const kill = () => t.remove();
  x.addEventListener('click', kill);
  $('toasts').append(t);
  setTimeout(kill, hash ? 12000 : 6000);
}

// ---------------------------------------------------------------- routing
function parseHash() {
  const parts = location.hash.replace(/^#\/?/, '').split('/').map((p) => { try { return decodeURIComponent(p); } catch { return ''; } });
  const view = VIEWS.includes(parts[0]) ? parts[0] : 'overview';
  return { view, a: parts[1] || null, b: parts[2] || null };
}
function route() {
  const prev = S.route.view;
  S.route = parseHash();
  if (S.overlay === 'menu') hideOverlay();
  for (const v of document.querySelectorAll('.cx-view')) v.hidden = v.dataset.view !== S.route.view;
  for (const a of document.querySelectorAll('[data-nav]')) {
    if (a.dataset.nav === S.route.view) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  }
  if (S.route.view !== 'runs' && S.overlay === 'drawer') hideOverlay();
  renderView();
  if (prev !== S.route.view) { window.scrollTo(0, 0); $('main').focus({ preventScroll: true }); }
}
function renderView() {
  const v = S.route.view;
  if (v === 'overview') renderOverview();
  else if (v === 'agents') renderAgents();
  else if (v === 'approvals') renderApprovals();
  else if (v === 'incidents') renderIncidents();
  else if (v === 'policy') renderPolicy();
  else if (v === 'keys') renderKeys();
  else if (v === 'runs') renderRuns();
}
function renderAll() {
  renderHeader();
  renderBanners();
  if (S.route.view !== 'runs') renderView();
}

// ---------------------------------------------------------------- refresh and live stream
let refreshTimer = null;
let refreshing = false;
function scheduleRefresh(ms = 600) {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => refresh(), ms);
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  clearTimeout(refreshTimer);
  try {
    const st = await fetchJSON('/api/state', { timeout: 15000 });
    S.state = st;
    addFeed(st.activity || []);
    S.fail = 0;
    renderAll();
    S.fresh.clear();
    refreshTimer = setTimeout(() => refresh(), S.live === 'on' ? 30000 : 10000);
  } catch (e) {
    S.fail += 1;
    S.lastError = String(e.message || e).replace(/^\/api\/state:\s*/, '').slice(0, 120);
    const wait = Math.min(30000, 2000 * 2 ** (S.fail - 1));
    S.retryAt = Date.now() + wait;
    renderBanners();
    if (!S.state) $('ov-sub').textContent = 'The vault did not answer yet.';
    refreshTimer = setTimeout(() => refresh(), wait);
  } finally {
    refreshing = false;
  }
}

function connect() {
  if (!('EventSource' in window)) { setLive('off', 'Polling'); return; }
  const es = new EventSource('/api/events');
  let offTimer = null;
  es.onopen = () => { clearTimeout(offTimer); offTimer = null; setLive('on', 'Live'); };
  es.onerror = () => {
    if (offTimer) return;
    offTimer = setTimeout(() => {
      offTimer = null;
      if (es.readyState === EventSource.OPEN) return;
      setLive('off', 'Reconnecting');
      scheduleRefresh(600);
    }, 8000);
  };
  es.addEventListener('status', (m) => {
    let d;
    try { d = JSON.parse(m.data); } catch { return; }
    if (!d || typeof d !== 'object') return;
    if (d.error) { setLive('wait', 'RPC error', String(d.error).slice(0, 200)); return; }
    setLive('on', 'Live');
    if (!S.state) return;
    if (d.stats) S.state.stats = d.stats;
    if (S.state.config) {
      const changed = S.state.config.paused !== d.paused || (d.pending != null && S.state.config.pending !== d.pending);
      if (d.paused != null) S.state.config.paused = d.paused;
      if (d.pause_reason !== undefined) S.state.config.pause_reason = d.pause_reason;
      if (d.activity_written != null) S.state.config.activity_written = d.activity_written;
      if (changed) scheduleRefresh(300);
    }
    renderHeader();
    renderBanners();
    if (S.route.view === 'overview') renderOverview();
  });
  es.addEventListener('activity', (m) => {
    let list;
    try { list = JSON.parse(m.data); } catch { return; }
    if (!Array.isArray(list)) return;
    addFeed(list, true);
    if (S.route.view === 'overview' || S.route.view === 'incidents' || S.route.view === 'agents') renderView();
    if (list.some((e) => e && (e.kind === 'tripped' || e.kind === 'frozen'))) toast('An agent tripped and was frozen.', 'stop');
    scheduleRefresh(600);
  });
}

// ---------------------------------------------------------------- ticker
function tick() {
  const now = Date.now();
  for (const n of document.querySelectorAll('[data-at]')) { const t = relTime(n.getAttribute('data-at'), now); if (t && n.textContent !== t) n.textContent = t; }
  for (const n of document.querySelectorAll('[data-exp]')) n.textContent = countdown(n.getAttribute('data-exp'));
  const r = document.querySelector('[data-retry]');
  if (r) r.textContent = `${Math.max(0, Math.ceil((S.retryAt - now) / 1000))}s`;
}

// ---------------------------------------------------------------- wiring
function init() {
  initToken();
  for (const r of skeletonRows(5)) $('ov-incidents').append(r);
  window.addEventListener('hashchange', route);
  wide.addEventListener?.('change', () => { if (S.route.view === 'agents') renderAgents(); });
  $('vault-copy').addEventListener('click', () => S.state?.vaultId && copyText($('vault-copy'), S.state.vaultId));
  $('menu-btn').addEventListener('click', () => (S.overlay === 'menu' ? hideOverlay() : showOverlay('menu')));
  $('scrim').addEventListener('click', () => { if (S.overlay === 'drawer') closeDrawer(); else hideOverlay(); });
  for (const b of document.querySelectorAll('#menu-sheet [data-close]')) b.addEventListener('click', hideOverlay);
  for (const b of document.querySelectorAll('#drawer [data-close]')) b.addEventListener('click', () => closeDrawer());
  for (const a of document.querySelectorAll('#menu-sheet a[data-nav]')) a.addEventListener('click', () => hideOverlay());
  $('in-filters').addEventListener('click', (e) => {
    const b = e.target.closest('.cx-filter');
    if (!b) return;
    S.filter = FILTERS[b.dataset.filter] ? b.dataset.filter : 'all';
    renderIncidents();
  });
  $('in-more').addEventListener('click', loadOlder);
  $('run-refresh').addEventListener('click', async () => {
    const b = $('run-refresh');
    b.disabled = true;
    try { await loadRuns(true); } catch { /* the view shows the error */ }
    b.disabled = false;
    renderRuns();
  });
  $('run-pick').addEventListener('change', (e) => { const v = e.target.value; if (RUN_ID_RE.test(v)) location.hash = `#runs/${encodeURIComponent(v)}`; });
  $('confirm-form').addEventListener('submit', submitConfirm);
  $('confirm-cancel').addEventListener('click', cancelConfirm);
  $('confirm-reason').addEventListener('input', updateHint);
  $('confirm').addEventListener('click', (e) => { if (e.target === $('confirm')) cancelConfirm(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && S.overlay) {
      e.preventDefault();
      if (S.overlay === 'confirm') cancelConfirm(); else if (S.overlay === 'drawer') closeDrawer(); else hideOverlay();
      return;
    }
    trapFocus(e);
  });
  route();
  refresh();
  connect();
  setInterval(tick, 1000);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
