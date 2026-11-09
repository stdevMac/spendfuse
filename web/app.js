// app.js - Spendfuse console. Plain browser JS, no build step.
// Every chain value is untrusted: it is inserted with textContent / createElement only.
'use strict';

(() => {
  // ------------------------------------------------------------ constants
  const NEAR = 10n ** 24n;
  const ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
  const HASH_RE = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;
  const U_RE = /^(0|[1-9]\d{0,38})$/;
  const TOKEN_RE = /^[A-Za-z0-9_-]{20,128}$/;
  const EXPLORERS = { testnet: 'https://testnet.nearblocks.io', mainnet: 'https://nearblocks.io' };
  const FEED_MAX = 300;

  // ------------------------------------------------------------ state
  const S = {
    token: null,
    state: null,
    feed: new Map(), // seq -> entry
    oldestSeq: null,
    runs: [],
    activeRun: null,
    busy: false,
  };

  // ------------------------------------------------------------ dom helpers
  const $ = (id) => document.getElementById(id);
  /** el('div', {class: 'x'}, 'text', childNode) - strings become text nodes. */
  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') n.className = v;
        else if (k === 'text') n.textContent = v;
        else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, String(v));
      }
    }
    for (const c of children.flat()) {
      if (c === undefined || c === null || c === false) continue;
      n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return n;
  }
  const clear = (n) => n.replaceChildren();

  // ------------------------------------------------------------ formatting
  const isAccount = (v) => typeof v === 'string' && v.length >= 2 && v.length <= 64 && ACCOUNT_RE.test(v);
  const isHash = (v) => typeof v === 'string' && HASH_RE.test(v);
  function toBig(v) {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
    if (typeof v === 'string' && U_RE.test(v)) return BigInt(v);
    return null;
  }
  /** yocto -> "1.2345" with BigInt math only. */
  function fmtNear(v, digits = 4) {
    const y = toBig(v);
    if (y === null) return '?';
    const whole = y / NEAR;
    const frac = (y % NEAR).toString().padStart(24, '0').slice(0, digits).replace(/0+$/, '');
    return frac ? `${whole}.${frac}` : `${whole}`;
  }
  const nearText = (v, digits) => `${fmtNear(v, digits)} NEAR`;
  function pct(part, whole) {
    const p = toBig(part);
    const w = toBig(whole);
    if (p === null || w === null || w === 0n) return 0;
    const x = Number((p * 1000n) / w) / 10;
    return Math.max(0, Math.min(100, x));
  }
  function fmtTime(ms) {
    const n = toBig(ms);
    if (n === null) return '';
    const d = new Date(Number(n));
    return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
  }
  function ago(ms) {
    const n = toBig(ms);
    if (n === null) return '';
    const s = Math.round((Date.now() - Number(n)) / 1000);
    if (s < 0) return 'just now';
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
  const short = (s, n = 160) => {
    const t = String(s);
    return t.length > n ? `${t.slice(0, n - 1)}…` : t;
  };
  function explorerBase() {
    const net = S.state && S.state.network;
    return EXPLORERS[net] || EXPLORERS.testnet;
  }
  /** Account id as a link when valid, plain text otherwise. */
  function accountNode(id, cls) {
    if (!isAccount(id)) return el('span', { class: `mono ${cls || ''} invalid`, title: 'not a valid account id' }, short(String(id ?? ''), 64));
    return el('a', { class: `mono ${cls || ''}`, href: `${explorerBase()}/address/${id}`, target: '_blank', rel: 'noopener noreferrer' }, id);
  }
  function txNode(hash, label) {
    if (!isHash(hash)) return null;
    return el('a', { class: 'mono tx', href: `${explorerBase()}/txns/${hash}`, target: '_blank', rel: 'noopener noreferrer' }, label || `${hash.slice(0, 8)}…`);
  }

  // ------------------------------------------------------------ token + api
  function initToken() {
    let t = null;
    try {
      const u = new URL(location.href);
      const q = u.searchParams.get('token');
      if (q && TOKEN_RE.test(q)) {
        t = q;
        try {
          sessionStorage.setItem('spendfuse-token', q);
        } catch {}
      }
      if (u.searchParams.has('token')) {
        u.searchParams.delete('token');
        history.replaceState(null, '', u.pathname + (u.search || '') + u.hash);
      }
    } catch {}
    if (!t) {
      try {
        const s = sessionStorage.getItem('spendfuse-token');
        if (s && TOKEN_RE.test(s)) t = s;
      } catch {}
    }
    S.token = t;
  }

  async function getJson(path) {
    const r = await fetch(path, { headers: { accept: 'application/json' }, cache: 'no-store' });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
    return body;
  }

  async function post(action, body) {
    if (!S.token) throw new Error('no token');
    const r = await fetch(`/api/${action}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-spendfuse-token': S.token },
      body: JSON.stringify(body || {}),
    });
    const out = await r.json().catch(() => ({}));
    if (!r.ok && !out.error) out.error = `HTTP ${r.status}`;
    return out;
  }

  const canDo = (action) => !!(S.token && S.state && S.state.mode && S.state.mode.actions && S.state.mode.allowed.includes(action));

  function banner(text, kind, link) {
    const b = $('banner');
    clear(b);
    b.className = `banner banner-${kind || 'info'}`;
    b.append(el('span', null, text));
    if (link) b.append(' ', link);
    b.append(el('button', { class: 'btn btn-ghost small', onclick: () => (b.hidden = true) }, 'dismiss'));
    b.hidden = false;
  }

  async function runAction(action, body, label) {
    if (S.busy) return;
    if (!confirm(`${label}?\nThis signs and sends a transaction from the ${S.state.mode.role} account.`)) return;
    S.busy = true;
    document.body.classList.add('busy');
    try {
      const out = await post(action, body);
      const link = txNode(out.hash, 'view tx');
      if (out.ok) banner(`${label}: done.`, 'ok', link);
      else banner(`${label} failed: ${out.error || 'unknown error'}`, 'err', link);
    } catch (e) {
      banner(`${label} failed: ${e.message}`, 'err');
    } finally {
      S.busy = false;
      document.body.classList.remove('busy');
      refresh();
    }
  }

  function askReason(what) {
    const r = prompt(`Reason for ${what} (optional, shown on chain):`, '');
    if (r === null) return null;
    return r.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200);
  }

  // ------------------------------------------------------------ render: header + stats
  function renderHeader(st) {
    const link = $('vault-link');
    link.textContent = st.vaultId || '?';
    if (isAccount(st.vaultId)) link.href = `${explorerBase()}/address/${st.vaultId}`;
    else link.removeAttribute('href');
    $('network').textContent = st.network || 'testnet';
    setPill(st.config ? st.config.paused : null, st.config ? st.config.pause_reason : null);

    const mode = $('mode');
    if (st.mode.readonly) {
      mode.textContent = 'read-only';
      mode.className = 'tag';
    } else if (st.mode.actions && S.token) {
      mode.textContent = `${st.mode.role} controls`;
      mode.className = 'tag tag-armed';
    } else if (st.mode.actions) {
      mode.textContent = 'view (no token)';
      mode.className = 'tag';
    } else {
      mode.textContent = 'view';
      mode.className = 'tag';
    }

    const va = $('vault-actions');
    const paused = !!(st.config && st.config.paused);
    $('btn-pause').hidden = !(canDo('pause') && !paused);
    $('btn-unpause').hidden = !(canDo('unpause') && paused);
    va.hidden = $('btn-pause').hidden && $('btn-unpause').hidden;
    $('signer-info').textContent = st.mode.signer ? `signing as ${st.mode.signer}` : '';
  }

  function setPill(paused, reason) {
    const p = $('vault-pill');
    if (paused === null || paused === undefined) {
      p.className = 'pill pill-unknown';
      p.textContent = 'UNKNOWN';
      p.title = '';
    } else if (paused) {
      p.className = 'pill pill-paused';
      p.textContent = 'PAUSED';
      p.title = reason ? `Paused: ${reason}` : 'Paused';
    } else {
      p.className = 'pill pill-active';
      p.textContent = 'ACTIVE';
      p.title = 'Vault accepting payment requests';
    }
  }

  function stat(label, value, cls) {
    return el('div', { class: `stat ${cls || ''}` }, el('div', { class: 'stat-value' }, value), el('div', { class: 'stat-label' }, label));
  }

  function renderStats(st) {
    const box = $('stats');
    clear(box);
    const s = st.stats;
    const c = st.config;
    if (!s || !c) {
      box.append(el('div', { class: 'muted' }, 'Stats unavailable.'));
      return;
    }
    box.append(
      stat('available', nearText(c.available, 3)),
      stat('paid out', nearText(s.paid_total, 3), 'good'),
      stat('requests', String(s.requests)),
      stat('paid', String(s.paid), 'good'),
      stat('escalated', String(s.escalated), 'warn'),
      stat('blocked', String(s.blocked), 'bad'),
      stat('canary trips', String(s.tripped), 'trip'),
      stat('freezes', String(s.freezes), 'bad'),
    );
  }

  // ------------------------------------------------------------ render: agents
  function renderAgents(st) {
    const body = $('agents-body');
    clear(body);
    const agents = Array.isArray(st.agents) ? st.agents : [];
    $('agents-count').textContent = String(agents.length);
    if (!agents.length) {
      body.append(el('tr', null, el('td', { colspan: '8', class: 'muted' }, st.errors && st.errors.agents ? `Unavailable: ${st.errors.agents}` : 'No agents registered.')));
      return;
    }
    for (const a of agents) {
      const frozen = a.status && a.status.state === 'frozen';
      const statusCell = el(
        'td',
        null,
        el('span', { class: `pill ${frozen ? 'pill-frozen' : 'pill-active'}` }, frozen ? 'FROZEN' : 'ACTIVE'),
        frozen ? el('div', { class: 'small reason' }, short(a.status.reason || '', 120)) : null,
        frozen ? el('div', { class: 'small muted' }, 'by ', accountNode(a.status.by), ` · ${ago(a.status.at_ms)}`) : null,
      );
      const p = pct(a.spent_24h, a.policy && a.policy.daily_limit);
      const bar = el('div', { class: `bar ${p >= 90 ? 'bar-hot' : p >= 60 ? 'bar-warm' : ''}` }, el('span', { class: 'bar-fill' }));
      bar.firstChild.style.width = `${p}%`;
      const spendCell = el(
        'td',
        { class: 'spend' },
        el('div', { class: 'small' }, `${fmtNear(a.spent_24h)} / ${nearText(a.policy.daily_limit)}`),
        bar,
        toBig(a.reserved) ? el('div', { class: 'small muted' }, `reserved ${nearText(a.reserved)}`) : null,
      );
      const ct = a.counters || {};
      const counters = el(
        'td',
        { class: 'small counters' },
        el('span', { class: 'c-good' }, `${ct.paid ?? 0} paid`),
        el('span', { class: 'c-warn' }, `${ct.escalated ?? 0} esc`),
        el('span', { class: 'c-bad' }, `${ct.blocked ?? 0} blk`),
        ct.tripped ? el('span', { class: 'c-trip' }, `${ct.tripped} trip`) : null,
      );
      const actions = el('td', { class: 'row-actions' });
      if (!frozen && canDo('freeze')) {
        actions.append(
          el('button', {
            class: 'btn btn-danger small',
            onclick: () => {
              const reason = askReason(`freezing ${a.agent_id}`);
              if (reason === null) return;
              runAction('freeze', { agent_id: a.agent_id, reason: reason || undefined }, `Freeze ${a.agent_id}`);
            },
          }, 'Freeze'),
        );
      }
      if (frozen && canDo('unfreeze')) {
        actions.append(el('button', { class: 'btn small', onclick: () => runAction('unfreeze', { agent_id: a.agent_id }, `Unfreeze ${a.agent_id}`) }, 'Unfreeze'));
      }
      const policy = a.policy || {};
      body.append(
        el(
          'tr',
          { class: frozen ? 'row-frozen' : '' },
          el('td', null, accountNode(a.agent_id), el('div', { class: 'small muted' }, short(a.label || '', 64)), policy.allowlist_only ? el('span', { class: 'tag small' }, 'allowlist only') : null),
          statusCell,
          spendCell,
          el('td', { class: 'small' }, nearText(policy.max_per_payment), el('div', { class: 'muted' }, `approval > ${fmtNear(policy.approval_threshold)}`)),
          el('td', { class: 'small' }, `${a.payments_last_hour ?? 0} / ${policy.max_payments_per_hour ?? '?'}`, el('div', { class: 'muted' }, `${a.blocks_last_hour ?? 0} blocks`)),
          el('td', null, String(a.payee_count ?? 0)),
          counters,
          actions,
        ),
      );
    }
  }

  // ------------------------------------------------------------ render: pending
  function renderPending(st) {
    const box = $('pending-list');
    clear(box);
    const list = Array.isArray(st.pending) ? st.pending : [];
    $('pending-count').textContent = String(list.length);
    if (!list.length) {
      box.append(el('div', { class: 'empty' }, st.errors && st.errors.pending ? `Unavailable: ${st.errors.pending}` : 'Nothing waiting for approval.'));
      return;
    }
    for (const p of list) {
      const btns = el('div', { class: 'item-actions' });
      if (U_RE.test(String(p.id))) {
        if (canDo('approve')) btns.append(el('button', { class: 'btn btn-ok small', onclick: () => runAction('approve', { request_id: String(p.id) }, `Approve request #${p.id}`) }, 'Approve'));
        if (canDo('reject'))
          btns.append(
            el('button', {
              class: 'btn btn-danger small',
              onclick: () => {
                const reason = askReason(`rejecting #${p.id}`);
                if (reason === null) return;
                runAction('reject', { request_id: String(p.id), reason: reason || undefined }, `Reject request #${p.id}`);
              },
            }, 'Reject'),
          );
      }
      box.append(
        el(
          'div',
          { class: 'item pending' },
          el('div', { class: 'item-main' },
            el('div', null, el('span', { class: 'mono muted' }, `#${p.id} `), accountNode(p.agent_id), el('span', { class: 'arrow' }, ' → '), accountNode(p.receiver_id), el('strong', { class: 'amount' }, ` ${nearText(p.amount)}`)),
            el('div', { class: 'small' }, ...(p.reasons || []).map((r) => el('span', { class: 'reason-chip' }, String(r)))),
            p.memo ? el('div', { class: 'memo small' }, el('span', { class: 'muted' }, 'memo (untrusted): '), short(p.memo, 256)) : null,
            el('div', { class: 'small muted' }, `requested ${ago(p.created_at_ms)} · expires ${fmtTime(p.expires_at_ms)}`),
          ),
          btns,
        ),
      );
    }
  }

  // ------------------------------------------------------------ render: feed
  const KIND_CLASS = {
    paid: 'ev-paid',
    approved: 'ev-paid',
    escalated: 'ev-escalated',
    blocked: 'ev-blocked',
    rejected: 'ev-blocked',
    transfer_failed: 'ev-blocked',
    expired: 'ev-muted',
    frozen: 'ev-frozen',
    paused: 'ev-frozen',
    tripped: 'ev-tripped',
    unfrozen: 'ev-info',
    unpaused: 'ev-info',
    reported: 'ev-escalated',
    blocklisted: 'ev-blocked',
  };

  function addFeed(entries) {
    for (const e of entries) {
      if (!e || typeof e !== 'object' || !U_RE.test(String(e.seq))) continue;
      S.feed.set(String(e.seq), e);
    }
    const keys = [...S.feed.keys()].sort((a, b) => (BigInt(b) > BigInt(a) ? 1 : -1));
    for (const k of keys.slice(FEED_MAX)) S.feed.delete(k);
    S.oldestSeq = keys.length ? keys[Math.min(keys.length, FEED_MAX) - 1] : null;
  }

  function feedItem(e, fresh) {
    const kind = String(e.kind || '?');
    const cls = KIND_CLASS[kind] || 'ev-info';
    const tripped = kind === 'tripped';
    const line = el(
      'div',
      { class: 'feed-line' },
      el('span', { class: `ev ${cls}` }, tripped ? 'CANARY TRIP' : kind.replace(/_/g, ' ')),
      e.agent_id ? accountNode(e.agent_id) : null,
      e.receiver_id ? el('span', { class: 'arrow' }, ' → ') : null,
      e.receiver_id ? accountNode(e.receiver_id) : null,
      e.amount ? el('strong', { class: 'amount' }, ` ${nearText(e.amount)}`) : null,
      e.request_id ? el('span', { class: 'mono muted' }, ` #${e.request_id}`) : null,
    );
    return el(
      'li',
      { class: `feed-item ${cls}-row ${fresh ? 'fresh' : ''}` },
      line,
      Array.isArray(e.reasons) && e.reasons.length ? el('div', { class: 'small' }, ...e.reasons.map((r) => el('span', { class: 'reason-chip' }, String(r)))) : null,
      e.note ? el('div', { class: 'small note' }, short(e.note, 200)) : null,
      el('div', { class: 'small muted' }, `#${e.seq} · ${fmtTime(e.at_ms)} · by `, accountNode(e.by), e.block_height ? ` · block ${e.block_height}` : ''),
    );
  }

  function renderFeed(freshSeqs) {
    const ol = $('feed');
    clear(ol);
    const keys = [...S.feed.keys()].sort((a, b) => (BigInt(b) > BigInt(a) ? 1 : -1));
    if (!keys.length) ol.append(el('li', { class: 'empty' }, 'No activity yet.'));
    for (const k of keys) ol.append(feedItem(S.feed.get(k), freshSeqs && freshSeqs.has(k)));
    $('feed-more').hidden = !(S.oldestSeq && S.oldestSeq !== '0' && keys.length >= 10);
  }

  async function loadOlder() {
    if (!S.oldestSeq) return;
    try {
      const r = await getJson(`/api/activity?before=${encodeURIComponent(S.oldestSeq)}&limit=50`);
      const before = S.feed.size;
      addFeed(r.activity || []);
      renderFeed();
      if (S.feed.size === before) $('feed-more').hidden = true;
    } catch (e) {
      banner(`Could not load older activity: ${e.message}`, 'err');
    }
  }

  // ------------------------------------------------------------ render: proof
  function renderProof(st) {
    const box = $('proof');
    clear(box);
    const proofs = Array.isArray(st.keys) ? st.keys : [];
    if (!proofs.length) {
      box.append(el('div', { class: 'empty' }, 'No agent accounts to inspect yet.'));
      return;
    }
    for (const pr of proofs) {
      const verdict = pr.error
        ? el('span', { class: 'pill pill-unknown' }, 'UNREADABLE')
        : pr.fullAccess > 0
          ? el('span', { class: 'pill pill-frozen' }, `${pr.fullAccess} FULL-ACCESS KEY${pr.fullAccess > 1 ? 'S' : ''}`)
          : pr.fcOnly
            ? el('span', { class: 'pill pill-active' }, 'FUNCTION-CALL ONLY')
            : el('span', { class: 'pill pill-paused' }, 'CHECK KEYS');
      const keys = el('ul', { class: 'keys' });
      for (const k of pr.keys || []) {
        keys.append(
          el(
            'li',
            { class: k.fullAccess ? 'key key-full' : 'key' },
            el('div', { class: 'mono small key-pk', title: String(k.publicKey) }, short(String(k.publicKey), 60)),
            k.fullAccess
              ? el('div', { class: 'small c-bad' }, 'FullAccess')
              : el(
                  'div',
                  { class: 'small' },
                  el('span', { class: 'tag small' }, 'FunctionCall'),
                  ' receiver ',
                  accountNode(k.receiverId, isAccount(k.receiverId) && k.receiverId === st.vaultId ? 'c-good' : 'c-bad'),
                  el('div', null, 'methods ', ...(k.methodNames || []).map((m) => el('code', { class: 'method' }, String(m)))),
                  el('div', { class: 'muted' }, `gas allowance ${k.allowance === null || k.allowance === undefined ? 'unlimited' : nearText(k.allowance)} · deposits: impossible`),
                ),
          ),
        );
      }
      box.append(
        el(
          'div',
          { class: 'proof' },
          el('div', { class: 'proof-head' }, accountNode(pr.accountId), verdict),
          pr.error ? el('div', { class: 'small muted' }, short(pr.error, 200)) : keys,
        ),
      );
    }
  }

  // ------------------------------------------------------------ render: blocklist + config
  function renderBlocklist(st) {
    const box = $('blocklist');
    clear(box);
    const list = Array.isArray(st.blocklist) ? st.blocklist : [];
    $('blocklist-count').textContent = String(list.length);
    if (!list.length) {
      box.append(el('div', { class: 'empty' }, 'No blocked receivers.'));
      return;
    }
    for (const b of list) {
      box.append(
        el(
          'div',
          { class: 'item' },
          el('div', { class: 'item-main' },
            el('div', null, accountNode(b.account_id), ' ', el('span', { class: `tag small ${b.status === 'confirmed' ? 'tag-bad' : 'tag-warn'}` }, String(b.status)), el('span', { class: 'muted small' }, ` ${b.reports ?? 0} report(s)`)),
            el('div', { class: 'small' }, short(b.reason || '', 200)),
            b.evidence ? el('div', { class: 'small muted' }, 'evidence: ', short(b.evidence, 200)) : null,
            el('div', { class: 'small muted' }, 'reported by ', accountNode(b.reporter), ` · ${ago(b.at_ms)}`),
          ),
        ),
      );
    }
  }

  function renderConfig(st) {
    const dl = $('config');
    clear(dl);
    const c = st.config;
    if (!c) {
      dl.append(el('dt', null, 'status'), el('dd', null, st.errors && st.errors.config ? `Unavailable: ${st.errors.config}` : 'Unavailable'));
      return;
    }
    const rows = [
      ['contract', `v${c.version}`],
      ['owner', accountNode(c.owner_id)],
      ['pending owner', c.pending_owner ? accountNode(c.pending_owner) : 'none'],
      ['guardians', c.guardians.length ? el('span', null, ...c.guardians.flatMap((g, i) => (i ? [', ', accountNode(g)] : [accountNode(g)]))) : 'none'],
      ['balance', `${nearText(c.balance)} = storage ${fmtNear(c.storage_locked)} + reserved ${fmtNear(c.reserved)} + available ${fmtNear(c.available)}`],
      ['canaries', `${c.canaries} hidden receivers (sha256 only)`],
      ['pause reason', c.paused ? short(c.pause_reason || '(none)', 200) : '-'],
      ['activity written', String(c.activity_written)],
    ];
    for (const [k, v] of rows) dl.append(el('dt', null, k), el('dd', null, v));
  }

  // ------------------------------------------------------------ load
  async function refresh() {
    try {
      const st = await getJson('/api/state');
      S.state = st;
      renderHeader(st);
      renderStats(st);
      renderAgents(st);
      renderPending(st);
      addFeed(Array.isArray(st.activity) ? st.activity : []);
      renderFeed();
      renderProof(st);
      renderBlocklist(st);
      renderConfig(st);
      const errs = Object.entries(st.errors || {});
      if (errs.length && !st.config) banner(`Vault not readable yet: ${short(errs[0][1], 200)}`, 'warn');
      $('updated').textContent = `updated ${new Date(st.fetchedAt || Date.now()).toLocaleTimeString()}`;
    } catch (e) {
      $('updated').textContent = `load failed: ${e.message}`;
    }
  }

  let refreshTimer = null;
  const scheduleRefresh = () => {
    if (refreshTimer) return;
    refreshTimer = setTimeout(() => {
      refreshTimer = null;
      refresh();
    }, 600);
  };

  function connect() {
    if (!('EventSource' in window)) return;
    const es = new EventSource('/api/events');
    const live = $('live');
    // The hosted (Worker) server ends each stream after ~25 s and the browser reconnects at once,
    // so only show "reconnecting" when the reconnect has not succeeded within a few seconds.
    let offTimer = null;
    es.onopen = () => {
      clearTimeout(offTimer);
      offTimer = null;
      live.className = 'live live-on';
      live.textContent = 'live';
    };
    es.onerror = () => {
      if (offTimer) return;
      offTimer = setTimeout(() => {
        offTimer = null;
        if (es.readyState === EventSource.OPEN) return;
        live.className = 'live live-off';
        live.textContent = 'reconnecting';
      }, 8000);
    };
    es.addEventListener('status', (m) => {
      let d;
      try {
        d = JSON.parse(m.data);
      } catch {
        return;
      }
      if (d.error) {
        live.className = 'live live-warn';
        live.textContent = 'rpc error';
        live.title = short(d.error, 200);
        return;
      }
      live.className = 'live live-on';
      live.textContent = 'live';
      live.title = '';
      setPill(d.paused, d.pause_reason);
      if (S.state && d.stats) {
        S.state.stats = d.stats;
        if (S.state.config) S.state.config.paused = d.paused;
        renderStats(S.state);
      }
    });
    es.addEventListener('activity', (m) => {
      let list;
      try {
        list = JSON.parse(m.data);
      } catch {
        return;
      }
      if (!Array.isArray(list)) return;
      const fresh = new Set(list.map((e) => String(e && e.seq)));
      addFeed(list);
      renderFeed(fresh);
      if (list.some((e) => e && (e.kind === 'tripped' || e.kind === 'frozen'))) document.title = '⚠ Spendfuse Console';
      scheduleRefresh();
    });
  }

  // ------------------------------------------------------------ runs
  const pick = (o, keys) => {
    for (const k of keys) if (o && o[k] !== undefined && o[k] !== null && o[k] !== '') return o[k];
    return undefined;
  };
  const scalar = (v) => (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? String(v) : v === null ? 'null' : short(JSON.stringify(v), 300));

  async function loadRuns() {
    const ul = $('runs');
    clear(ul);
    try {
      const r = await getJson('/api/runs');
      S.runs = Array.isArray(r.runs) ? r.runs : [];
    } catch (e) {
      ul.append(el('li', { class: 'empty' }, `Could not list runs: ${e.message}`));
      return;
    }
    if (!S.runs.length) {
      ul.append(el('li', { class: 'empty' }, 'No runs yet. Run the attack demo to record one.'));
      return;
    }
    for (const run of S.runs) {
      const title = pick(run, ['title', 'scenario', 'name']) || run.id;
      ul.append(
        el(
          'li',
          { class: `item run-item ${S.activeRun === run.id ? 'active' : ''}` },
          el('button', { class: 'run-btn', onclick: () => openRun(run.id) },
            el('div', null, short(String(title), 80)),
            el('div', { class: 'small muted' }, `${run.mode ? `${run.mode} · ` : ''}${run.count !== undefined ? `${run.count} steps · ` : ''}${new Date(run.mtimeMs).toLocaleString()}`),
          ),
        ),
      );
    }
  }

  function stepClass(s) {
    const t = String(pick(s, ['status', 'verdict', 'outcome', 'result', 'kind', 'type', 'event']) || '').toLowerCase();
    if (/trip|canary/.test(t)) return 'ev-tripped';
    if (/frozen|freeze/.test(t)) return 'ev-frozen';
    if (/block|reject|fail|denied|error|attack|inject/.test(t)) return 'ev-blocked';
    if (/escalat|pending|warn|approval/.test(t)) return 'ev-escalated';
    if (/paid|allow|ok|success|approved|pass/.test(t)) return 'ev-paid';
    return 'ev-info';
  }

  const STEP_KNOWN = new Set(['t', 'at', 'ts', 'time', 'at_ms', 'timestamp', 'kind', 'type', 'event', 'step', 'phase', 'title', 'label', 'message', 'summary', 'text', 'detail', 'details', 'note', 'hash', 'txHash', 'tx_hash', 'tx', 'status', 'verdict', 'outcome', 'result']);

  function renderStep(s, i) {
    if (!s || typeof s !== 'object') return el('li', { class: 'tl-item ev-info-row' }, el('div', { class: 'tl-body' }, scalar(s)));
    const kind = pick(s, ['kind', 'type', 'event', 'phase', 'step']);
    const title = pick(s, ['title', 'label', 'message', 'summary', 'text']);
    const detail = pick(s, ['detail', 'details', 'note']);
    const status = pick(s, ['status', 'verdict', 'outcome', 'result']);
    const when = pick(s, ['at_ms', 'ts', 'timestamp', 'at', 't', 'time']);
    const hash = pick(s, ['hash', 'txHash', 'tx_hash', 'tx']);
    const cls = stepClass(s);
    const extras = el('dl', { class: 'kv small' });
    for (const [k, v] of Object.entries(s)) {
      if (STEP_KNOWN.has(k)) continue;
      const vNode = isAccount(v) && /id$|receiver|agent|account|to$|from$/i.test(k) ? accountNode(v) : el('span', { class: 'mono' }, scalar(v));
      extras.append(el('dt', null, k), el('dd', null, vNode));
    }
    let whenText = '';
    if (typeof when === 'number' || (typeof when === 'string' && U_RE.test(when))) whenText = Number(when) > 1e11 ? new Date(Number(when)).toLocaleTimeString() : `+${when}`;
    else if (typeof when === 'string') whenText = short(when, 40);
    return el(
      'li',
      { class: `tl-item ${cls}-row` },
      el('div', { class: 'tl-dot' }),
      el('div', { class: 'tl-body' },
        el('div', { class: 'tl-head' },
          el('span', { class: 'mono muted' }, `${i + 1}`),
          kind !== undefined ? el('span', { class: `ev ${cls}` }, short(scalar(kind), 40)) : null,
          status !== undefined && typeof status !== 'object' ? el('span', { class: 'tag small' }, short(scalar(status), 40)) : null,
          whenText ? el('span', { class: 'small muted' }, whenText) : null,
          txNode(typeof hash === 'string' ? hash : null),
        ),
        title !== undefined ? el('div', { class: 'tl-title' }, short(scalar(title), 400)) : null,
        detail !== undefined ? el('div', { class: 'small note' }, short(scalar(detail), 600)) : null,
        status !== undefined && typeof status === 'object' ? el('pre', { class: 'small mono pre' }, short(JSON.stringify(status, null, 2), 1200)) : null,
        extras.childNodes.length ? extras : null,
      ),
    );
  }

  async function openRun(id) {
    S.activeRun = id;
    const head = $('run-head');
    const meta = $('run-meta');
    const tl = $('run-timeline');
    clear(head);
    clear(meta);
    clear(tl);
    head.append(el('h2', null, 'Loading…'));
    for (const li of document.querySelectorAll('.run-item')) li.classList.remove('active');
    let run;
    try {
      const r = await getJson(`/api/runs/${encodeURIComponent(id)}`);
      run = r.run;
    } catch (e) {
      clear(head);
      head.append(el('h2', null, `Run ${short(id, 60)}: ${e.message}`));
      return;
    }
    clear(head);
    const title = (run && pick(run, ['title', 'scenario', 'name'])) || id;
    head.append(el('h2', null, short(scalar(title), 120)));
    const steps = run && typeof run === 'object' ? (Array.isArray(run) ? run : ['steps', 'events', 'timeline', 'entries'].map((k) => run[k]).find(Array.isArray)) : null;
    if (run && typeof run === 'object' && !Array.isArray(run)) {
      for (const [k, v] of Object.entries(run)) {
        if (Array.isArray(v) && v === steps) continue;
        if (['title', 'scenario', 'name'].includes(k)) continue;
        const node = typeof v === 'object' && v !== null ? el('pre', { class: 'mono pre small' }, short(JSON.stringify(v, null, 2), 2000)) : isAccount(v) && /id$|vault|agent|owner/i.test(k) ? accountNode(v) : isHash(v) ? txNode(v, v) : scalar(v);
        meta.append(el('dt', null, k), el('dd', null, node));
      }
    }
    if (!steps || !steps.length) {
      tl.append(el('li', { class: 'empty' }, 'No steps in this run.'));
      return;
    }
    steps.slice(0, 1000).forEach((s, i) => tl.append(renderStep(s, i)));
    loadRuns();
  }

  // ------------------------------------------------------------ tabs + boot
  function showTab(name) {
    for (const b of document.querySelectorAll('.tab')) {
      const on = b.dataset.tab === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', String(on));
    }
    $('tab-console').hidden = name !== 'console';
    $('tab-runs').hidden = name !== 'runs';
    if (name === 'runs') loadRuns();
    try {
      sessionStorage.setItem('spendfuse-tab', name);
    } catch {}
  }

  function boot() {
    initToken();
    for (const b of document.querySelectorAll('.tab')) b.addEventListener('click', () => showTab(b.dataset.tab));
    $('feed-more').addEventListener('click', loadOlder);
    $('runs-refresh').addEventListener('click', loadRuns);
    $('btn-pause').addEventListener('click', () => {
      const reason = askReason('pausing the vault');
      if (reason === null) return;
      runAction('pause', { reason: reason || undefined }, 'Pause vault');
    });
    $('btn-unpause').addEventListener('click', () => runAction('unpause', {}, 'Unpause vault'));
    let tab = 'console';
    try {
      tab = sessionStorage.getItem('spendfuse-tab') === 'runs' ? 'runs' : 'console';
    } catch {}
    showTab(tab);
    refresh();
    connect();
    setInterval(() => {
      if (!document.hidden) refresh();
    }, 30000);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
