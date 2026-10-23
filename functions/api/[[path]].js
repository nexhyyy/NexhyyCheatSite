/**
 * Nexhyyy — backend for Cloudflare Pages Functions (route: /api/*)
 *
 * Setup (see README.md):
 *   • KV namespace binding ........ NX
 *   • Secret ...................... ADMIN_PASSWORD  – password of the owner account (min 8 chars)
 *   • Secret ...................... TOKEN_SECRET    – long random string used to sign sessions
 *   • Variable (optional) ......... ADMIN_USERNAME  – defaults to "nexhyyy"
 *   • Variable (optional) ......... PBKDF2_ITER     – defaults to 100000 (lower it if the free plan hits the CPU limit)
 *
 * Security model
 *   – Admin rights are issued ONLY to ADMIN_USERNAME after the password from ADMIN_PASSWORD is verified on the server.
 *     That name is reserved: nobody can register it. Every /admin/* route re-checks the signed token.
 *   – Passwords: PBKDF2-SHA256 + random salt. Sessions: HMAC-signed tokens.
 *   – Licence keys: ~150 bits of randomness, stored server-side only, one activation each.
 */

const ALPH = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const PLANS = {
  '1d':   { days: 1,    code: 'D1' },
  '7d':   { days: 7,    code: 'D7' },
  '30d':  { days: 30,   code: 'M1' },
  'life': { days: null, code: 'LT' }
};
const ROLES = ['user', 'media', 'admin1', 'admin2', 'admin3', 'owner'];
const KEY_RE = /^NX-(D1|D7|M1|LT)-([A-Z2-9]{6}-){4}[A-Z2-9]{6}$/;
const USER_RE = /^[A-Za-z0-9_.-]{3,20}$/;
const URL_RE = /^https?:\/\/[^\s"'<>]{3,480}$/i;
const DAY = 86400000;

class HttpError extends Error {
  constructor(code, status = 400) { super(code); this.code = code; this.status = status; }
}
const fail = (code, status) => { throw new HttpError(code, status); };

const enc = new TextEncoder();
const json = (data, status = 200, cache = 'no-store') =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': cache, 'x-content-type-options': 'nosniff' }
  });

/* ---------- crypto helpers ---------- */
const b64u = buf => {
  let s = '';
  const a = new Uint8Array(buf);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64u = str => {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const s = atob(str), a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
};
const sha256 = async s => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([sha256(String(a)), sha256(String(b))]);
  let r = 0;
  for (let i = 0; i < x.length; i++) r |= x[i] ^ y[i];
  return r === 0;
}
async function pbkdf2(password, saltB64, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64u(saltB64), iterations: iter }, key, 256);
  return b64u(bits);
}
const iterOf = env => Math.max(10000, Math.min(100000, parseInt(env.PBKDF2_ITER, 10) || 100000));
async function newPassword(env, password) {
  const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
  const iter = iterOf(env);
  return { salt, iter, hash: await pbkdf2(password, salt, iter) };
}

/* ---------- tokens ---------- */
const secretOf = env => env.TOKEN_SECRET || ('nx:' + env.ADMIN_PASSWORD);
const hmacKey = env => crypto.subtle.importKey('raw', enc.encode(secretOf(env)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
async function makeToken(env, payload) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const sig = b64u(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(body)));
  return body + '.' + sig;
}
async function readToken(env, token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  let ok = false;
  try { ok = await crypto.subtle.verify('HMAC', await hmacKey(env), unb64u(sig), enc.encode(body)); } catch { return null; }
  if (!ok) return null;
  try {
    const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
    return p && p.e > Date.now() ? p : null;
  } catch { return null; }
}

/* ---------- storage helpers ---------- */
const adminName = env => (env.ADMIN_USERNAME || 'nexhyyy');
const adminLower = env => adminName(env).toLowerCase();
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

const userMeta = u => ({ display: u.display, role: u.role, lifetime: !!u.lifetime, expiresAt: u.expiresAt || null, banned: !!u.banned, created: u.created });
const saveUser = (env, lower, u) => env.NX.put('u:' + lower, JSON.stringify(u), { metadata: userMeta(u) });
async function loadUser(env, lower) {
  const raw = await env.NX.get('u:' + lower);
  return raw ? JSON.parse(raw) : null;
}
const isAdminName = (env, lower) => lower === adminLower(env);

/* The owner account has a stored profile record too (avatar, banner, history) but NO password hash. */
async function loadAdminRec(env) {
  const lower = adminLower(env);
  let rec = await loadUser(env, lower);
  if (!rec) {
    rec = { id: crypto.randomUUID(), display: adminName(env), salt: '', iter: 0, hash: '', role: 'owner', avatar: '', banner: '', banned: false, lifetime: true, expiresAt: null, periodStart: Date.now(), created: Date.now(), lastLogin: Date.now(), history: [] };
    await saveUser(env, lower, rec);
  }
  rec.role = 'owner'; rec.lifetime = true; rec.banned = false;
  return rec;
}

const pubUser = (u, env) => ({
  id: u.id, username: u.display, role: ROLES.includes(u.role) ? u.role : 'user',
  admin: isAdminName(env, u.display.toLowerCase()),
  avatar: u.avatar || '', banner: u.banner || '', bio: u.bio || '',
  logins: (u.logins || []).slice(0, 10),
  lifetime: !!u.lifetime, expiresAt: u.expiresAt || null, periodStart: u.periodStart || null,
  banned: !!u.banned, created: u.created, lastLogin: u.lastLogin || null,
  history: (u.history || []).slice(0, 50)
});

async function listAll(env, prefix) {
  const out = [];
  let cursor;
  do {
    const r = await env.NX.list({ prefix, cursor, limit: 1000 });
    out.push(...r.keys);
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor);
  return out;
}
const uaLabel = req => {
  const u = req.headers.get('user-agent') || '';
  const b = /NexhyyyLauncher/.test(u) ? 'Launcher' : /Edg\//.test(u) ? 'Edge' : /OPR\//.test(u) ? 'Opera' : /Chrome\//.test(u) ? 'Chrome' : /Firefox\//.test(u) ? 'Firefox' : /Safari\//.test(u) ? 'Safari' : 'Browser';
  const o = /Windows/.test(u) ? 'Windows' : /Android/.test(u) ? 'Android' : /iPhone|iPad/.test(u) ? 'iOS' : /Mac OS/.test(u) ? 'macOS' : /Linux/.test(u) ? 'Linux' : '?';
  return b + ' · ' + o;
};
const pushLogin = (rec, req) => { rec.logins = [{ ts: Date.now(), ua: uaLabel(req) }, ...(rec.logins || [])].slice(0, 10); };
const clean = (v, max) => str(v, max).replace(/[\u0000-\u001f\u007f]/g, ' ');
const maskKey = k => { const p = k.split('-'); return `${p[0]}-${p[1]}-${p[2]}-******-******-******-${p[6]}`; };

function applyPlan(u, planId) {
  const p = PLANS[planId];
  if (!p) fail('invalid');
  const now = Date.now();
  if (p.days === null) {
    u.lifetime = true;
    if (!u.periodStart) u.periodStart = now;
  } else {
    const active = u.expiresAt && u.expiresAt > now;
    if (!active) u.periodStart = now;
    u.expiresAt = Math.max(now, u.expiresAt || 0) + p.days * DAY;
  }
  return p;
}
function pushHistory(u, key, planId) {
  const p = PLANS[planId];
  u.history = [{ key: maskKey(key), plan: planId, ts: Date.now(), days: p.days }, ...(u.history || [])].slice(0, 50);
}
const readList = async (env, k) => { const raw = await env.NX.get(k); try { return raw ? JSON.parse(raw) : []; } catch { return []; } };

/* ---------- admin audit log ---------- */
async function audit(env, act, target, info) {
  const list = await readList(env, 'audit');
  list.unshift({ id: crypto.randomUUID(), ts: Date.now(), by: adminName(env), act, target: target || '', info: String(info || '').slice(0, 160) });
  await env.NX.put('audit', JSON.stringify(list.slice(0, 300)));
}
/* public team list is cached in KV ('team') so visitors never trigger KV list operations */
async function rebuildTeam(env) {
  const ul = await listAll(env, 'u:');
  const staff = ul.filter(x => x.metadata && x.metadata.role && x.metadata.role !== 'user' && !x.metadata.banned).slice(0, 30);
  const recs = (await Promise.all(staff.map(x => loadUser(env, x.name.slice(2))))).filter(Boolean);
  const ord = r => ROLES.indexOf(r);
  const team = recs.map(r => ({ username: r.display, role: ROLES.includes(r.role) ? r.role : 'user', avatar: r.avatar || '', bio: r.bio || '' }))
    .sort((a, b) => ord(b.role) - ord(a.role));
  await env.NX.put('team', JSON.stringify(team));
}

/* ---------- rate limit (best effort) ---------- */
async function rateLimit(env, request, action, max, windowSec) {
  const ip = request.headers.get('cf-connecting-ip') || 'x';
  const slot = Math.floor(Date.now() / (windowSec * 1000));
  const k = `rl:${action}:${ip}:${slot}`;
  const n = parseInt(await env.NX.get(k), 10) || 0;
  if (n >= max) fail('toomany', 429);
  try { await env.NX.put(k, String(n + 1), { expirationTtl: Math.max(60, windowSec * 2) }); } catch {}
}

/* ---------- auth ---------- */
async function auth(request, env, { admin = false } = {}) {
  const h = request.headers.get('authorization') || '';
  const p = await readToken(env, h.startsWith('Bearer ') ? h.slice(7) : '');
  if (!p) fail('forbidden', 401);
  if (p.r === 'admin') {
    if (p.u !== adminLower(env)) fail('forbidden', 403);
    return { lower: p.u, role: 'admin', rec: await loadAdminRec(env) };
  }
  if (admin) fail('forbidden', 403);
  const rec = await loadUser(env, p.u);
  if (!rec || isAdminName(env, p.u)) fail('forbidden', 401);
  if (rec.banned) fail('banned', 403);
  return { lower: p.u, role: 'user', rec };
}

function genKey(planId) {
  const grp = () => {
    const a = new Uint8Array(6);
    crypto.getRandomValues(a);
    let s = '';
    for (const x of a) s += ALPH[x & 31];
    return s;
  };
  return `NX-${PLANS[planId].code}-${grp()}-${grp()}-${grp()}-${grp()}-${grp()}`;
}

/* ---------- routes ---------- */
const routes = {
  'GET /ping': async (req, env) => json({ ok: true, live: !!(env.NX && env.ADMIN_PASSWORD && String(env.ADMIN_PASSWORD).length >= 8) }),

  'POST /register': async (req, env, body) => {
    const username = str(body.username, 20), password = typeof body.password === 'string' ? body.password : '';
    if (!USER_RE.test(username) || password.length < 6 || password.length > 100) fail('invalid');
    const lower = username.toLowerCase();
    if (isAdminName(env, lower)) fail('reserved', 403);
    await rateLimit(env, req, 'reg', 10, 3600);
    if (await env.NX.get('u:' + lower)) fail('exists', 409);
    const now = Date.now();
    const rec = { id: crypto.randomUUID(), display: username, ...(await newPassword(env, password)), role: 'user', avatar: '', banner: '', bio: '', banned: false, lifetime: false, expiresAt: null, periodStart: null, created: now, lastLogin: now, history: [], logins: [] };
    pushLogin(rec, req);
    await saveUser(env, lower, rec);
    const token = await makeToken(env, { u: lower, r: 'user', e: now + 30 * DAY });
    return json({ token, user: pubUser(rec, env) });
  },

  'POST /login': async (req, env, body) => {
    const username = str(body.username, 20), password = typeof body.password === 'string' ? body.password : '';
    if (!USER_RE.test(username) || !password || password.length > 100) fail('badcreds', 401);
    await rateLimit(env, req, 'login', 15, 600);
    const lower = username.toLowerCase();
    if (isAdminName(env, lower)) {
      await rateLimit(env, req, 'adm', 5, 900); // owner login: max 5 attempts / 15 min per IP
      await new Promise(r => setTimeout(r, 400)); // slow down guessing
      if (!(await safeEqual(password, env.ADMIN_PASSWORD))) fail('badcreds', 401);
      const rec = await loadAdminRec(env);
      rec.lastLogin = Date.now(); pushLogin(rec, req);
      await saveUser(env, lower, rec);
      try { await rebuildTeam(env); } catch {}
      const token = await makeToken(env, { u: lower, r: 'admin', e: Date.now() + 4 * 3600e3 });
      return json({ token, user: pubUser(rec, env) });
    }
    const rec = await loadUser(env, lower);
    const hash = rec ? await pbkdf2(password, rec.salt, rec.iter || 100000) : '';
    if (!rec || !(await safeEqual(hash, rec.hash))) fail('badcreds', 401);
    if (rec.banned) fail('banned', 403);
    rec.lastLogin = Date.now(); pushLogin(rec, req);
    await saveUser(env, lower, rec);
    const token = await makeToken(env, { u: lower, r: 'user', e: Date.now() + 30 * DAY });
    return json({ token, user: pubUser(rec, env) });
  },

  'GET /me': async (req, env) => {
    const a = await auth(req, env);
    return json({ user: pubUser(a.rec, env) });
  },

  'POST /redeem': async (req, env, body) => {
    const a = await auth(req, env);
    const key = str(body.key, 60).toUpperCase();
    if (!KEY_RE.test(key)) fail('nokey', 404);
    await rateLimit(env, req, 'redeem', 20, 600);
    const { metadata: meta } = await env.NX.getWithMetadata('k:' + key);
    if (!meta) fail('nokey', 404);
    if (meta.usedBy) fail('used', 409);
    if (meta.assignedTo && meta.assignedTo !== a.lower) fail('nokey', 404);
    applyPlan(a.rec, meta.plan);
    pushHistory(a.rec, key, meta.plan);
    // mark the key first, then grant — a failure can never grant the same key twice
    await env.NX.put('k:' + key, '1', { metadata: { ...meta, usedBy: a.rec.display, usedAt: Date.now() } });
    await saveUser(env, a.lower, a.rec);
    return json({ user: pubUser(a.rec, env) });
  },

  'GET /inbox': async (req, env) => {
    const a = await auth(req, env);
    const [global, mine] = await Promise.all([readList(env, 'inbox'), readList(env, 'm:' + a.lower)]);
    const messages = [...global.map(m => ({ ...m, private: false })), ...mine.map(m => ({ ...m, private: true }))].sort((x, y) => y.ts - x.ts);
    return json({ messages });
  },

  'POST /profile': async (req, env, body) => {
    const a = await auth(req, env);
    const avatar = str(body.avatar, 500), banner = str(body.banner, 500);
    if ((avatar && !URL_RE.test(avatar)) || (banner && !URL_RE.test(banner))) fail('url');
    a.rec.avatar = avatar; a.rec.banner = banner;
    if (typeof body.bio === 'string') a.rec.bio = clean(body.bio, 140);
    await saveUser(env, a.lower, a.rec);
    if (a.rec.role && a.rec.role !== 'user') { try { await rebuildTeam(env); } catch {} }
    return json({ user: pubUser(a.rec, env) });
  },

  'POST /password': async (req, env, body) => {
    const a = await auth(req, env);
    if (a.role === 'admin') fail('forbidden', 403);
    const oldP = typeof body.oldPassword === 'string' ? body.oldPassword : '', newP = typeof body.newPassword === 'string' ? body.newPassword : '';
    if (newP.length < 6 || newP.length > 100) fail('invalid');
    await rateLimit(env, req, 'pw', 10, 600);
    if (!(await safeEqual(await pbkdf2(oldP, a.rec.salt, a.rec.iter || 100000), a.rec.hash))) fail('oldpass', 403);
    Object.assign(a.rec, await newPassword(env, newP));
    await saveUser(env, a.lower, a.rec);
    return json({ ok: true });
  },

  /* ----- admin only ----- */
  'GET /admin/state': async (req, env) => {
    await auth(req, env, { admin: true });
    const [uk, kk, inbox, auditL, tickets, annRaw] = await Promise.all([listAll(env, 'u:'), listAll(env, 'k:'), readList(env, 'inbox'), readList(env, 'audit'), readList(env, 'tickets'), env.NX.get('announce')]);
    let announce = { text: '', on: false }; try { if (annRaw) announce = JSON.parse(annRaw); } catch {}
    const recs = await Promise.all(uk.slice(0, 1000).map(x => loadUser(env, x.name.slice(2))));
    const users = recs.filter(Boolean).map(r => pubUser(r, env)).sort((a, b) => b.created - a.created);
    const keys = kk.map(x => ({ key: x.name.slice(2), ...(x.metadata || {}) })).sort((a, b) => (b.created || 0) - (a.created || 0));
    return json({ users, keys, inbox, audit: auditL, tickets, announce });
  },

  'POST /admin/keys': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const plan = str(body.plan, 8);
    if (!PLANS[plan]) fail('invalid');
    const count = Math.min(100, Math.max(1, parseInt(body.count, 10) || 1));
    const assignTo = str(body.assignTo, 20).toLowerCase();
    let target = null;
    if (assignTo) {
      if (!USER_RE.test(assignTo)) fail('invalid');
      target = await loadUser(env, assignTo);
      if (!target) fail('nouser', 404);
    }
    const now = Date.now(), keys = [];
    for (let i = 0; i < count; i++) keys.push(genKey(plan));
    const auto = !!body.autoActivate && !!target;
    await audit(env, 'keys', assignTo, count + '× ' + plan + (auto ? ' (auto)' : ''));
    await Promise.all(keys.map(k => env.NX.put('k:' + k, '1', { metadata: { plan, created: now, createdBy: adminName(env), assignedTo: assignTo || null, usedBy: auto ? target.display : null, usedAt: auto ? now : null } })));
    if (target) {
      if (auto) {
        for (const k of keys) { applyPlan(target, plan); pushHistory(target, k, plan); }
        await saveUser(env, assignTo, target);
      } else {
        const list = await readList(env, 'm:' + assignTo);
        list.unshift({ id: crypto.randomUUID(), title: 'Your key', body: keys.join('\n'), ts: now, from: adminName(env) });
        await env.NX.put('m:' + assignTo, JSON.stringify(list.slice(0, 100)));
      }
    }
    return json({ keys });
  },

  'POST /admin/key-delete': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const key = str(body.key, 60).toUpperCase();
    if (!KEY_RE.test(key)) fail('invalid');
    await env.NX.delete('k:' + key);
    await audit(env, 'key-delete', '', maskKey(key));
    return json({ ok: true });
  },

  'POST /admin/user-delete': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const lower = str(body.name, 20).toLowerCase();
    if (!USER_RE.test(lower) || isAdminName(env, lower)) fail('self', 403);
    await Promise.all([env.NX.delete('u:' + lower), env.NX.delete('m:' + lower)]);
    await audit(env, 'user-delete', lower, '');
    try { await rebuildTeam(env); } catch {}
    return json({ ok: true });
  },

  'POST /admin/user-ban': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const lower = str(body.name, 20).toLowerCase();
    if (!USER_RE.test(lower) || isAdminName(env, lower)) fail('self', 403);
    const rec = await loadUser(env, lower);
    if (!rec) fail('nouser', 404);
    rec.banned = !!body.banned;
    await saveUser(env, lower, rec);
    await audit(env, rec.banned ? 'ban' : 'unban', lower, '');
    try { await rebuildTeam(env); } catch {}
    return json({ ok: true });
  },

  'POST /admin/user-grant': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const lower = str(body.name, 20).toLowerCase();
    const rec = USER_RE.test(lower) ? await loadUser(env, lower) : null;
    if (!rec) fail('nouser', 404);
    applyPlan(rec, str(body.plan, 8));
    await saveUser(env, lower, rec);
    await audit(env, 'grant', lower, str(body.plan, 8));
    return json({ ok: true });
  },

  'POST /admin/user-role': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const lower = str(body.name, 20).toLowerCase(), role = str(body.role, 10);
    if (!ROLES.includes(role)) fail('role');
    if (!USER_RE.test(lower) || isAdminName(env, lower)) fail('self', 403);
    const rec = await loadUser(env, lower);
    if (!rec) fail('nouser', 404);
    rec.role = role;
    await saveUser(env, lower, rec);
    await audit(env, 'role', lower, role);
    try { await rebuildTeam(env); } catch {}
    return json({ ok: true });
  },

  'POST /admin/user-password': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const lower = str(body.name, 20).toLowerCase(), password = typeof body.password === 'string' ? body.password : '';
    if (!USER_RE.test(lower) || isAdminName(env, lower)) fail('self', 403);
    if (password.length < 6 || password.length > 100) fail('invalid');
    const rec = await loadUser(env, lower);
    if (!rec) fail('nouser', 404);
    Object.assign(rec, await newPassword(env, password));
    await saveUser(env, lower, rec);
    await audit(env, 'password', lower, '');
    return json({ ok: true });
  },

  'POST /admin/inbox': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const title = str(body.title, 80), text = str(body.body, 2000), to = str(body.to, 20).toLowerCase();
    if (!title || !text) fail('invalid');
    const msg = { id: crypto.randomUUID(), title, body: text, ts: Date.now(), from: adminName(env) };
    if (to) {
      if (!USER_RE.test(to) || !(await env.NX.get('u:' + to))) fail('nouser', 404);
      const list = await readList(env, 'm:' + to);
      list.unshift(msg);
      await env.NX.put('m:' + to, JSON.stringify(list.slice(0, 100)));
    } else {
      const list = await readList(env, 'inbox');
      list.unshift(msg);
      await env.NX.put('inbox', JSON.stringify(list.slice(0, 200)));
    }
    await audit(env, 'message', to, title);
    return json({ ok: true });
  },

  'POST /admin/inbox-delete': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const id = str(body.id, 80);
    const list = (await readList(env, 'inbox')).filter(m => m.id !== id);
    await env.NX.put('inbox', JSON.stringify(list));
    await audit(env, 'message-delete', '', id.slice(0, 8));
    return json({ ok: true });
  },

  /* ----- public data (cached, no auth) ----- */
  'GET /public': async (req, env) => {
    const [annRaw, teamRaw] = await Promise.all([env.NX.get('announce'), env.NX.get('team')]);
    let announce = null, team = [];
    try { const a = annRaw && JSON.parse(annRaw); if (a && a.on && a.text) announce = { text: a.text, ts: a.ts || 0 }; } catch {}
    try { team = teamRaw ? JSON.parse(teamRaw) : []; } catch {}
    return json({ announce, team }, 200, 'public, max-age=30');
  },

  /* ----- support tickets ----- */
  'POST /ticket': async (req, env, body) => {
    const a = await auth(req, env);
    if (a.role === 'admin') fail('forbidden', 403);
    const subject = clean(body.subject, 80), text = str(body.body, 1500);
    if (!subject || !text) fail('invalid');
    await rateLimit(env, req, 'ticket', 5, 3600);
    const list = await readList(env, 'tickets');
    list.unshift({ id: crypto.randomUUID(), user: a.rec.display, subject, body: text, ts: Date.now(), status: 'open' });
    await env.NX.put('tickets', JSON.stringify(list.slice(0, 300)));
    return json({ ok: true });
  },
  'GET /tickets': async (req, env) => {
    const a = await auth(req, env);
    const list = await readList(env, 'tickets');
    return json({ tickets: list.filter(x => x.user.toLowerCase() === a.lower).slice(0, 30).map(x => ({ id: x.id, subject: x.subject, ts: x.ts, status: x.status, reply: x.reply || '' })) });
  },

  /* ----- delete my own account ----- */
  'POST /account-delete': async (req, env, body) => {
    const a = await auth(req, env);
    if (a.role === 'admin') fail('forbidden', 403);
    await rateLimit(env, req, 'pw', 10, 600);
    const pw = typeof body.password === 'string' ? body.password : '';
    if (!(await safeEqual(await pbkdf2(pw, a.rec.salt, a.rec.iter || 100000), a.rec.hash))) fail('oldpass', 403);
    await Promise.all([env.NX.delete('u:' + a.lower), env.NX.delete('m:' + a.lower)]);
    const list = (await readList(env, 'tickets')).filter(x => x.user.toLowerCase() !== a.lower);
    await env.NX.put('tickets', JSON.stringify(list));
    if (a.rec.role && a.rec.role !== 'user') { try { await rebuildTeam(env); } catch {} }
    return json({ ok: true });
  },

  /* ----- admin: announcement, tickets ----- */
  'POST /admin/announce': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const text = clean(body.text, 200), on = !!body.on && !!text;
    await env.NX.put('announce', JSON.stringify({ text, on, ts: Date.now() }));
    await audit(env, on ? 'announce-on' : 'announce-off', '', text);
    return json({ ok: true });
  },
  'POST /admin/ticket-reply': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const id = str(body.id, 80), text = str(body.text, 2000);
    if (!id || !text) fail('invalid');
    const list = await readList(env, 'tickets');
    const t = list.find(x => x.id === id);
    if (!t) fail('nouser', 404);
    const to = t.user.toLowerCase();
    const mine = await readList(env, 'm:' + to);
    mine.unshift({ id: crypto.randomUUID(), title: 'Re: ' + t.subject, body: text, ts: Date.now(), from: adminName(env) });
    await env.NX.put('m:' + to, JSON.stringify(mine.slice(0, 100)));
    t.status = 'answered'; t.reply = text.slice(0, 500); t.repliedAt = Date.now();
    await env.NX.put('tickets', JSON.stringify(list));
    await audit(env, 'ticket-reply', to, t.subject);
    return json({ ok: true });
  },
  'POST /admin/ticket-delete': async (req, env, body) => {
    await auth(req, env, { admin: true });
    const id = str(body.id, 80);
    const list = (await readList(env, 'tickets')).filter(x => x.id !== id);
    await env.NX.put('tickets', JSON.stringify(list));
    await audit(env, 'ticket-delete', '', id.slice(0, 8));
    return json({ ok: true });
  }
};

export async function onRequest({ request, env }) {
  try {
    if (!env.NX) fail('network', 503);
    const path = new URL(request.url).pathname.replace(/^\/api/, '').replace(/\/+$/, '') || '/';
    const handler = routes[`${request.method} ${path}`];
    if (!handler) fail('invalid', 404);
    if (path !== '/ping' && !env.ADMIN_PASSWORD) fail('network', 503);
    let body = {};
    if (request.method === 'POST') {
      const text = await request.text();
      if (text.length > 20000) fail('invalid', 413);
      try { body = text ? JSON.parse(text) : {}; } catch { fail('invalid'); }
      if (!body || typeof body !== 'object') body = {};
    }
    return await handler(request, env, body);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.code }, e.status);
    return json({ error: 'network' }, 500);
  }
}
