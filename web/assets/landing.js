// Spendfuse landing: fills the hero window, the float card and the console preview from /api/state,
// and checks the proof cards against the recorded run from /api/runs. Read-only: no write path.
// Every value from the API enters the page through textContent or a validated attribute.
import { BASE58_TX, ACCOUNT, fetchJSON, formatNear, toNear, el, incidentRow, setBar, copyText, shortAccount, relTime } from './ui.js';

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const RUN_ID = /(^|live-run-)2026-11-09T04-59-38-380Z$/;
const PAYMENT_KINDS = new Set(['paid', 'blocked', 'escalated', 'tripped', 'frozen', 'rejected', 'approved', 'transfer_failed', 'expired']);
const OFFLINE = 'The vault did not answer. The recorded run below still links every transaction.';

const big = (v) => { try { return BigInt(String(v ?? '0')); } catch { return 0n; } };
const near = (v) => `${formatNear(v, { min: 0, max: 2 })} NEAR`;
const count = (v) => (Number.isFinite(Number(v)) ? Number(v).toLocaleString('en-US') : '?');
const text = (node, value) => { if (node) node.textContent = String(value); };

function setLive(node, state, label) {
  if (!node) return;
  node.setAttribute('data-state', state);
  node.textContent = label;
}

// newest first, payment outcomes before admin events
function pickIncidents(activity, n) {
  const list = Array.isArray(activity) ? activity.filter((e) => e && typeof e === 'object') : [];
  list.sort((a, b) => Number(b.seq) - Number(a.seq));
  const pay = list.filter((e) => PAYMENT_KINDS.has(e.kind));
  return (pay.length >= n ? pay : [...pay, ...list.filter((e) => !PAYMENT_KINDS.has(e.kind))]).slice(0, n);
}

// money actually moved: automatic plus owner-approved, minus transfers that failed and rolled back.
// The console's Paid figure uses the same formula, so both pages show one number.
const paidCount = (st) => Math.max(0, (Number(st.paid) || 0) + (Number(st.approved) || 0) - (Number(st.failed) || 0));

// at or above the daily limit, say so plainly: approved payments can sit above the agent's own limit
function spendLine(a, tight = false) {
  const p = a.policy ?? {};
  const limit = toNear(p.daily_limit);
  const used = toNear(a.spent_24h);
  if (limit > 0 && used >= limit) return tight ? `Limit reached · ${near(p.daily_limit)}` : `Daily limit reached · ${near(p.daily_limit)}`;
  return `${formatNear(a.spent_24h, { min: 0, max: 2 })} of ${near(p.daily_limit)}${tight ? '' : ' spent'}`;
}
function spendNote(a) {
  const p = a.policy ?? {};
  const limit = toNear(p.daily_limit);
  const used = toNear(a.spent_24h);
  if (!(limit > 0 && used >= limit)) return '';
  return `Further agent payments are blocked. ${formatNear(a.spent_24h, { min: 0, max: 2 })} NEAR moved in 24h, including owner-approved payments, which can sit above the agent's limit.`;
}

function fillHero(s, now) {
  const list = $('[data-hero-list]');
  const rows = pickIncidents(s.activity, 7);
  if (list) {
    if (rows.length) list.replaceChildren(...rows.map((e) => incidentRow(e, now)));
    else list.replaceChildren(el('li', { class: 'win__msg', text: 'No incidents logged yet.' }));
  }
  const st = s.stats ?? {};
  text($('[data-hero-count]'), `${count(st.requests)} requests · ${count(paidCount(st))} paid · ${count(st.blocked)} blocked`);
  const title = $('.hero-win .win__title');
  if (title && ACCOUNT.test(String(s.vaultId))) title.textContent = s.vaultId;

  const a = Array.isArray(s.agents) ? s.agents[0] : null;
  const value = $('[data-float-value]');
  const bar = $('[data-float-bar]');
  if (a?.policy) {
    text(value, spendLine(a));
    const limit = big(a.policy.daily_limit);
    if (bar) setBar(bar, limit > 0n ? toNear(a.spent_24h) / toNear(a.policy.daily_limit) : 0);
  } else {
    text(value, 'No agent registered');
  }
  text($('[data-float-line]'), (a?.policy && spendNote(a)) || `${count(st.blocked)} blocked · ${count(st.tripped)} tripped · ${count(st.freezes)} freezes, all time`);
}

function factRow(name, id, value) {
  return el('li', { class: 'arow' },
    el('span', { class: 'arow__name', text: name }),
    el('span', { class: 'arow__id', text: id, attrs: { title: id } }),
    el('span', { class: 'arow__val num', text: value }));
}

function statusChip(status) {
  const frozen = status?.state === 'frozen';
  return el('span', { class: `chip chip--${frozen ? 'trip' : 'ok'}`, text: frozen ? 'frozen' : 'active' });
}

function fillApp(s, now) {
  setLive($('[data-app-live]'), 'on', 'Live');
  const a = Array.isArray(s.agents) ? s.agents[0] : null;
  const cfg = s.config ?? {};
  const rows = $('[data-app-rows]');
  if (rows && a) {
    const keyCount = Array.isArray(s.keys) ? s.keys.reduce((n, k) => n + (Array.isArray(k.keys) ? k.keys.length : 0), 0) : 0;
    const allKeys = Array.isArray(s.keys) ? s.keys.flatMap((k) => (Array.isArray(k.keys) ? k.keys : [])) : [];
    const fullAccess = allKeys.filter((k) => k && k.fullAccess).length;
    const fcOnly = allKeys.length > 0 && allKeys.every((k) => k && !k.fullAccess && Array.isArray(k.methodNames) && k.methodNames.length);
    const methods = fcOnly ? [...new Set(allKeys.flatMap((k) => k.methodNames))] : null;
    const allow = Array.isArray(a.policy?.allowlist) ? a.policy.allowlist.filter((x) => ACCOUNT.test(String(x))) : [];
    const guardians = Array.isArray(cfg.guardians) ? cfg.guardians.filter((x) => ACCOUNT.test(String(x))) : [];
    const agentRow = el('li', { class: 'arow is-on' },
      el('span', { class: 'arow__name', text: a.label || shortAccount(a.agent_id, 28) }),
      el('span', { class: 'arow__id', text: a.agent_id, attrs: { title: a.agent_id } }),
      el('span', { class: 'arow__chip' }, statusChip(a.status)),
      el('span', { class: 'arow__val num', text: spendLine(a, true) }));
    rows.replaceChildren(agentRow,
      factRow('Allowlist', allow.join(', ') || 'none', count(allow.length)),
      factRow('Pending approvals', 'held for the owner, expire after 24h', count(cfg.pending ?? (Array.isArray(s.pending) ? s.pending.length : 0))),
      factRow('Canaries', 'planted payee hashes', count(cfg.canaries)),
      factRow('Guardians', guardians.join(', ') || 'none', count(guardians.length)),
      factRow('Blocklist', 'blocked payees', count(cfg.blocklist)),
      factRow('Keys', methods ? `function-call only: ${methods.join(', ')}` : `${count(keyCount)} keys, ${count(fullAccess)} full-access`, count(keyCount)),
      factRow(`Contract ${String(cfg.version ?? '')}`.trim(), `${near(cfg.available)} available`, s.network === 'testnet' ? 'testnet' : String(s.network ?? '')));
  }
  if (!a) return;
  text($('[data-open-name]'), a.label || a.agent_id);
  const open = $('[data-open-status]');
  if (open) { const chip = statusChip(a.status); chip.setAttribute('data-open-status', ''); open.replaceWith(chip); }
  const p = a.policy ?? {};
  text($('[data-lim-cap]'), near(p.max_per_payment));
  text($('[data-lim-day]'), spendLine(a, true));
  const daily = toNear(p.daily_limit);
  const day = $('[data-bar-day]');
  if (day) setBar(day, daily > 0 ? toNear(a.spent_24h) / daily : 0);
  const perHour = Number(p.max_payments_per_hour) || 0;
  text($('[data-lim-hour]'), `${count(a.payments_last_hour)} of ${count(perHour)}`);
  const hour = $('[data-bar-hour]');
  if (hour) setBar(hour, perHour > 0 ? Number(a.payments_last_hour) / perHour : 0);
  const set = Number(p.auto_freeze_after_blocks) || 0;
  const af = set > 0 ? set : 25; // 0 means the contract's backstop of 25
  text($('[data-lim-blocks]'), `${count(a.blocks_last_hour)} of ${count(af)}${set > 0 ? '' : ', backstop'}`);
  const blocks = $('[data-bar-blocks]');
  if (blocks) setBar(blocks, Number(a.blocks_last_hour) / af);

  const policy = $('[data-policy]');
  if (policy) {
    const allow = Array.isArray(p.allowlist) ? p.allowlist.filter((x) => ACCOUNT.test(String(x))) : [];
    const pairs = [
      ['max_per_payment', near(p.max_per_payment)],
      ['daily_limit', near(p.daily_limit)],
      ['approval_threshold', near(p.approval_threshold)],
      ['new_payee_limit', near(p.new_payee_limit)],
      ['max_payments_per_hour', count(perHour)],
      [p.allowlist_only ? 'allowlist (only)' : 'allowlist', allow.join(', ') || 'none'],
    ];
    policy.replaceChildren(...pairs.map(([k, v]) => el('div', {}, el('dt', { text: k }), el('dd', { text: v, attrs: { title: v } }))));
  }
  const inc = $('[data-open-inc]');
  if (inc) {
    const mine = pickIncidents((s.activity ?? []).filter((e) => e?.agent_id === a.agent_id), 4);
    inc.replaceChildren(...(mine.length ? mine.map((e) => incidentRow(e, now)) : [el('li', { class: 'win__msg', text: 'No incidents for this agent yet.' })]));
  }
}

function offline() {
  setLive($('[data-live]'), 'off', 'Offline');
  const list = $('[data-hero-list]');
  if (list) list.replaceChildren(el('li', { class: 'win__msg', text: OFFLINE }));
  text($('[data-hero-count]'), 'Not connected');
  text($('[data-float-value]'), 'Vault not reachable');
  text($('[data-float-line]'), 'The proof run below is recorded on chain.');
  const inc = $('[data-open-inc]');
  if (inc) inc.replaceChildren(el('li', { class: 'win__msg', text: OFFLINE }));
}

async function loadState() {
  try {
    const s = await fetchJSON('/api/state', { timeout: 12000 });
    if (!s || typeof s !== 'object' || !Array.isArray(s.activity)) throw new Error('bad state');
    const now = Date.now();
    setLive($('[data-live]'), 'on', 'Live');
    fillHero(s, now);
    fillApp(s, now);
  } catch {
    offline();
  }
  fitAll();
}

// the proof cards are static; the recorded run marks the links it contains and sets each pass state
async function loadRun() {
  try {
    const list = await fetchJSON('/api/runs', { timeout: 10000 });
    const hit = (list?.runs ?? []).find((r) => RUN_ID.test(String(r?.id)));
    if (!hit) return;
    const one = await fetchJSON(`/api/runs/${encodeURIComponent(hit.id)}`, { timeout: 10000 });
    const run = one?.run;
    if (!run || run.dryRun !== false || !Array.isArray(run.scenarios)) return;
    const hashes = new Set();
    for (const sc of [...run.scenarios].sort((a, b) => Number(a.n) - Number(b.n))) {
      for (const t of Array.isArray(sc.txs) ? sc.txs : []) if (BASE58_TX.test(String(t?.hash)) && t.ok !== false && !t.simulated) hashes.add(t.hash);
      const card = typeof sc.id === 'string' && /^[a-z-]{1,40}$/.test(sc.id) ? document.getElementById(`proof-${sc.id}`) : null;
      if (!card) continue;
      card.setAttribute('data-pass', sc.pass === true ? 'true' : 'false');
      text($('[data-pass]', card), sc.pass === true ? 'passed' : 'did not pass');
    }
    for (const a of $$('a[data-tx]')) {
      if (hashes.has(a.getAttribute('data-tx'))) {
        a.setAttribute('data-verified', '');
        a.setAttribute('title', 'Listed in the recorded run');
      }
    }
    const started = Date.parse(String(run.startedAt));
    if (Number.isFinite(started)) $$('[data-run-age]').forEach((n) => (n.textContent = relTime(started)));
  } catch { /* the static cards and links stand on their own */ }
}

// a window's body has a fixed frame: whatever does not fit whole is taken out (data-cut), never shown half
// clipped. Lists and card grids give way item by item, and a label goes with the list it heads.
const FIT_LISTS = 'ul, ol, dl, .limits';
function fitBody(body) {
  const units = [];
  for (const c of body.children) {
    if (c.matches(FIT_LISTS)) units.push(...c.children); else units.push(c);
  }
  for (const u of [...units, ...body.children]) u.toggleAttribute('data-cut', false);
  const box = body.getBoundingClientRect();
  if (!box.height) return;
  const pad = parseFloat(getComputedStyle(body).paddingBottom) || 0;
  const limit = box.bottom - pad + 0.5;
  let out = false;
  for (const u of units) {
    if (!out && u.getBoundingClientRect().bottom > limit) out = true;
    if (out) u.toggleAttribute('data-cut', true);
  }
  // a list left with nothing in it goes too, with the label over it
  for (const c of body.children) {
    if (c.matches(FIT_LISTS) && c.children.length && [...c.children].every((x) => x.hasAttribute('data-cut'))) {
      c.toggleAttribute('data-cut', true);
      const prev = c.previousElementSibling;
      if (prev?.classList.contains('open__label')) prev.toggleAttribute('data-cut', true);
    }
  }
}
let fitQueued = 0;
function fitAll() {
  clearTimeout(fitQueued);
  fitQueued = setTimeout(() => $$('.hero-win .win__body, .app .win__body').forEach(fitBody), 30);
}

function wireCopy() {
  for (const btn of $$('button[data-copy]')) btn.addEventListener('click', () => copyText(btn, btn.getAttribute('data-copy') ?? ''));
  const panelBtn = $('button[data-copy-panel]');
  if (panelBtn) panelBtn.addEventListener('click', () => {
    const panel = $('#code [role="tabpanel"]:not([hidden]) code');
    if (panel) copyText(panelBtn, panel.textContent ?? '');
  });
}

wireCopy();
fitAll();
addEventListener('resize', fitAll);
document.fonts?.ready.then(fitAll);
loadState();
loadRun();
