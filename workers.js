const SESSION_TOKEN_TTL_SECONDS = 3600;
const IDLE_SESSION_TIMEOUT_SECONDS = 900;
const MAX_PATH_LENGTH = 200;
const PBKDF2_ITERATIONS = 100_000;
const ITEMS_PER_PAGE = 13;
const PAGES_BASE_URL = 'https://short.yourdomain.com';

const te = new TextEncoder();
const KEY_RE = /^[a-zA-Z0-9-]+$/;

const toHex = (u8) => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => new Uint8Array((hex.match(/.{1,2}/g) || []).map(h => parseInt(h, 16)));

async function sha256Hex(input) {
  const data = typeof input === 'string' ? te.encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return toHex(new Uint8Array(digest));
}

function randomHex(nBytes) {
  const buf = new Uint8Array(nBytes);
  crypto.getRandomValues(buf);
  return toHex(buf);
}

async function hashPassword(password) {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  const key = await crypto.subtle.importKey('raw', te.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, key, 256);
  const hashHex = toHex(new Uint8Array(bits));
  return `pbkdf2:${PBKDF2_ITERATIONS}:${toHex(salt)}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  if (!stored || !password) return false;
  const parts = stored.split(':');
  if (parts[0] !== 'pbkdf2' || parts.length !== 4) {
    return false;
  }
  const iterations = parseInt(parts[1], 10);
  const saltHex = parts[2];
  const hashHex = parts[3];
  const key = await crypto.subtle.importKey('raw', te.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromHex(saltHex), iterations, hash: 'SHA-256' },
    key,
    256
  );
  const got = toHex(new Uint8Array(bits));
  return timingSafeEqual(got, hashHex);
}

function timingSafeEqual(a, b) {
  if (!a || !b) return false;
  const ua = typeof a === 'string' ? te.encode(a) : a;
  const ub = typeof b === 'string' ? te.encode(b) : b;
  if (ua.length !== ub.length) return false;
  let out = 0;
  for (let i = 0; i < ua.length; i++) out |= ua[i] ^ ub[i];
  return out === 0;
}

const allowed = ['https://short.yourdomain.com'];

function makeHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowOrigin = allowed.includes(origin) ? origin : allowed[0];

  const h = new Headers({
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self' https://short.yourdomain.com; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '0',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  });
  return h;
}

const noCache = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '0',
};

function json(body, status = 200, headers = new Headers()) {
  const h = new Headers(headers);
  h.set('Content-Type', 'application/json');
  for (const [k, v] of Object.entries(noCache)) h.set(k, v);
  return new Response(JSON.stringify(body), { status, headers: h });
}

function styledMessageResponse(message, status = 200, headers = new Headers()) {
  const h = new Headers(headers);
  h.set('Content-Type', 'text/html; charset=utf-8');
  for (const [k, v] of Object.entries(noCache)) h.set(k, v);
  const html = `<!doctype html><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>links</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#0b1220;color:#e6edf3}
    .card{background:#0f172a;border:1px solid #1e293b;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.4);padding:24px;max-width:540px}
    h1{font-weight:700;font-size:20px;margin:0 0 8px}
    p{margin:0;color:#9fb0c0}
  </style>
  <main class="card"><h1>${status}</h1><p>${message}</p></main>`;
  return new Response(html, { status, headers: h });
}

function parseCookies(request) {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return {};
  return Object.fromEntries(cookie.split(';').map(c => c.trim().split('=').map(decodeURIComponent)));
}

function setSessionCookie(h, token) {
  const cookie = [
    `session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Secure',
  ].join('; ');
  h.append('Set-Cookie', cookie);
}

function clearSessionCookie(h) {
  h.append('Set-Cookie', 'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure');
}

async function getValidSession(DB, request) {
  const cookies = parseCookies(request);
  const token = cookies.session;
  if (!token) return { valid: false, reason: 'no-session' };

  const row = await DB.prepare(
    `SELECT csrf_token, created_at, last_activity_at FROM sessions WHERE session_token = ?`
  ).bind(token).first();

  if (!row) return { valid: false, reason: 'not-found' };

  const now = Date.now();
  if (row.created_at + SESSION_TOKEN_TTL_SECONDS * 1000 < now) {
    return { valid: false, reason: 'expired' };
  }
  if (row.last_activity_at + IDLE_SESSION_TIMEOUT_SECONDS * 1000 < now) {
    return { valid: false, reason: 'idle' };
  }

  await DB.prepare(`UPDATE sessions SET last_activity_at = ? WHERE session_token = ?`).bind(now, token).run();
  return { valid: true, csrf: row.csrf_token, token };
}

async function requireAuth(DB, request) {
  const session = await getValidSession(DB, request);
  if (!session.valid) return { ok: false, status: 401, body: { authenticated: false, reason: session.reason } };
  return { ok: true, session };
}

async function requireCsrf(DB, request) {
  const session = await getValidSession(DB, request);
  if (!session.valid) return { ok: false, status: 401, body: { authenticated: false, reason: session.reason } };
  const headerToken = request.headers.get('X-CSRF-Token');
  if (!headerToken || !timingSafeEqual(headerToken, session.csrf)) {
    return { ok: false, status: 403, body: { error: 'CSRF token invalid' } };
  }
  return { ok: true, session };
}

async function readJsonOrForm(request) {
  const ct = request.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) {
    try {
      return await request.json();
    } catch {
      return {};
    }
  }
  try {
    const fd = await request.formData();
    return Object.fromEntries(fd.entries());
  } catch {
    return {};
  }
}

function normalizeKey(key) {
  key = (key || '').trim();
  if (!key) return '';
  if (key.startsWith('/')) key = key.slice(1);
  if (key.length > MAX_PATH_LENGTH) key = key.slice(0, MAX_PATH_LENGTH);
  return key;
}

async function getFolderDepth(DB, folderId) {
  let depth = 0;
  let current = folderId;
  while (current) {
    const parent = await DB.prepare(`SELECT parent_id FROM items WHERE id = ? AND type = 'folder'`).bind(current).first('parent_id');
    current = parent || null;
    if (current) depth++;
    if (depth > 32) break;
  }
  return depth;
}

async function isDescendant(DB, itemId, possibleAncestorId) {
  let current = await DB.prepare(`SELECT parent_id FROM items WHERE id = ?`).bind(itemId).first('parent_id');
  while (current) {
    if (current === possibleAncestorId) return true;
    current = await DB.prepare(`SELECT parent_id FROM items WHERE id = ?`).bind(current).first('parent_id');
  }
  return false;
}

async function deleteFolderRecursive(DB, id) {
  const children = (await DB.prepare(`SELECT id, type FROM items WHERE parent_id = ?`).bind(id).all()).results || [];
  for (const c of children) {
    if (c.type === 'folder') await deleteFolderRecursive(DB, c.id);
    else await DB.prepare(`DELETE FROM items WHERE id = ?`).bind(c.id).run();
  }
  await DB.prepare(`DELETE FROM items WHERE id = ?`).bind(id).run();
}

export default {
  async fetch(request, env) {
    const { DB } = env;
    const url = new URL(request.url);
    const pathname = url.pathname;
    const headers = makeHeaders(request, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    if (pathname === '/api/check-auth' && request.method === 'GET') {
      const auth = await requireAuth(DB, request);
      if (!auth.ok) return json(auth.body, 401, headers);
      return json({ authenticated: true }, 200, headers);
    }

    if (pathname === '/api/session-info' && request.method === 'GET') {
      const session = await getValidSession(DB, request);
      if (!session.valid) return json({ authenticated: false, reason: session.reason }, 401, headers);
      return json({ authenticated: true, csrfToken: session.csrf }, 200, headers);
    }

    if (pathname === '/api/login' && request.method === 'POST') {
      const body = await readJsonOrForm(request);
      const username = (body.username || '').trim();
      const password = body.password || '';

      const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
      const rlKey = `login:${ip}`;
      const now = Date.now();

      let attempts = 0, blockedUntil = 0, blockCount = 0;
      try {
        const rec = await DB.prepare(`SELECT attempts, blocked_until, block_count FROM login_attempts WHERE key = ?`).bind(rlKey).first();
        attempts = rec?.attempts || 0;
        blockedUntil = rec?.blocked_until || 0;
        blockCount = rec?.block_count || 0;
        if (blockedUntil && now < blockedUntil) {
          return styledMessageResponse('Too many attempts. Try again shortly.', 429, headers);
        }
      } catch (e) {}

      let ok = false;
      try {
        ok = await verifyPassword(password, env.ADMIN_PASS_PBKDF2) && (!env.ADMIN_USER_HASH || (await sha256Hex(username)) === env.ADMIN_USER_HASH);
      } catch { 
        ok = false; 
      }

      if (!ok) {
        try {
          attempts += 1;
          if (attempts % 5 === 0) {
            blockCount += 1;
            blockedUntil = now + Math.min(60_000 * blockCount, 10 * 60_000);
          }
          await DB.prepare(`INSERT INTO login_attempts (key, attempts, last_attempt_at, blocked_until, block_count) VALUES (?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET attempts=excluded.attempts, last_attempt_at=excluded.last_attempt_at, blocked_until=excluded.blocked_until, block_count=excluded.block_count`).bind(rlKey, attempts, now, blockedUntil, blockCount).run();
        } catch {}
        return json({ error: 'Invalid credentials' }, 401, headers);
      }

      const sessionToken = randomHex(32);
      const csrfToken = randomHex(32);
      await DB.prepare(`INSERT INTO sessions (session_token, csrf_token, created_at, last_activity_at) VALUES (?, ?, ?, ?)`).bind(sessionToken, csrfToken, now, now).run();

      const h = new Headers(headers);
      setSessionCookie(h, sessionToken);
      return json({ success: true, csrfToken }, 200, h);
    }

    if (pathname === '/api/logout' && request.method === 'POST') {
      const csrf = await requireCsrf(DB, request);
      if (!csrf.ok) return json(csrf.body, csrf.status, headers);
      await DB.prepare(`DELETE FROM sessions WHERE session_token = ?`).bind(csrf.session.token).run();
      const h = new Headers(headers); clearSessionCookie(h);
      return new Response('', { status: 204, headers: h });
    }


    if (pathname === '/api/admin' && request.method === 'GET') {
      const auth = await requireAuth(DB, request);
      if (!auth.ok) return json(auth.body, 401, headers);

      const params = url.searchParams;
      const base = `${url.origin}/`;
      
      const page = parseInt(params.get('page') || '1', 10);
      const folderId = params.get('folderId');
      const searchQuery = params.get('search');
      const sortBy = params.get('sortBy') || 'default';
      const sortOrder = params.get('sortOrder') === 'ASC' ? 'ASC' : 'DESC';

      const minClicks = parseInt(params.get('minClicks'), 10);
      const maxClicks = parseInt(params.get('maxClicks'), 10);
      const expiryStatus = params.get('expiryStatus');
      const creationDateFrom = parseInt(params.get('creationDateFrom'), 10);
      const creationDateTo = parseInt(params.get('creationDateTo'), 10);

      let whereClauses = [];
      let bindings = [];

      if (folderId && folderId !== 'null') {
          whereClauses.push('parent_id = ?');
          bindings.push(folderId);
      } else {
          whereClauses.push('parent_id IS NULL');
      }

      if (searchQuery) {
        whereClauses.push(`(id LIKE ? OR name LIKE ? OR original_url LIKE ?)`);
        bindings.push(`%${searchQuery}%`, `%${searchQuery}%`, `%${searchQuery}%`);
      }

      if (!isNaN(minClicks) && minClicks >= 0) {
          whereClauses.push('clicks >= ?');
          bindings.push(minClicks);
      }
      if (!isNaN(maxClicks) && maxClicks >= 0) {
          whereClauses.push('clicks <= ?');
          bindings.push(maxClicks);
      }
      if (!isNaN(creationDateFrom)) {
          whereClauses.push('created_at >= ?');
          bindings.push(creationDateFrom);
      }
      if (!isNaN(creationDateTo)) {
          whereClauses.push('created_at <= ?');
          bindings.push(creationDateTo);
      }

      const now = Date.now();
      switch (expiryStatus) {
          case 'never':
              whereClauses.push('(expires_at IS NULL OR expires_at = 0)');
              break;
          case 'expired':
              whereClauses.push(`( (expires_at IS NOT NULL AND expires_at < ?) OR (max_clicks IS NOT NULL AND clicks >= max_clicks) )`);
              bindings.push(now);
              break;
          case 'expiresSoon':
              const in24Hours = now + 24 * 60 * 60 * 1000;
              whereClauses.push(`( expires_at IS NOT NULL AND expires_at > ? AND expires_at < ? )`);
              bindings.push(now, in24Hours);
              break;
      }

      const whereString = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

      let orderByString = `ORDER BY
          CASE WHEN type = 'folder' THEN 0 ELSE 1 END ASC,
          CASE WHEN type = 'folder' THEN name END ASC`;

      const validSortColumnsForLinks = ['created_at', 'clicks', 'id'];
      if (validSortColumnsForLinks.includes(sortBy)) {
          orderByString += `, CASE WHEN type = 'link' THEN ${sortBy} END ${sortOrder}`;
      } else {
          orderByString += `, CASE WHEN type = 'link' THEN created_at END DESC`;
      }

      const offset = (page - 1) * ITEMS_PER_PAGE;
      const sql = `SELECT id, type, name, original_url, password_hash, max_clicks, clicks, expires_at, created_at, parent_id FROM items ${whereString} ${orderByString} LIMIT ? OFFSET ?`;
      const finalBindings = [...bindings, ITEMS_PER_PAGE, offset];
      
      const rows = (await DB.prepare(sql).bind(...finalBindings).all()).results || [];

      const countSql = `SELECT COUNT(*) as count FROM items ${whereString}`;
      const totalItems = (await DB.prepare(countSql).bind(...bindings).first()).count;
      const totalPages = Math.ceil(totalItems / ITEMS_PER_PAGE);

      const items = rows.map(r => {
        if (r.type === 'folder') {
          return { id: r.id, is_folder: true, name: r.name, parent_folder_id: r.parent_id || null, created: r.created_at };
        }
        return { id: r.id, key: r.id, is_folder: false, originalUrl: r.original_url, clicks: r.clicks || 0, maxClicks: r.max_clicks || 0, expirationTimestamp: r.expires_at || null, created: r.created_at, hasPassword: !!r.password_hash, fullShortUrl: new URL(r.id, base).toString() };
      });

      return json({ items, totalPages }, 200, headers);
    }

    if (pathname === '/api/create-folder' && request.method === 'POST') {
      const csrf = await requireCsrf(DB, request);
      if (!csrf.ok) return json(csrf.body, csrf.status, headers);
      const body = await readJsonOrForm(request);
      const name = (body.name || body.folderName || '').trim();
      let parentFolderId = body.parentFolderId ?? body.targetFolderId ?? null;
      if (parentFolderId === 'null' || parentFolderId === '') parentFolderId = null;

      if (!name) return json({ error: 'Folder name required' }, 400, headers);
      if (parentFolderId) {
        if (await getFolderDepth(DB, parentFolderId) >= 32) return json({ error: 'Folder depth limit reached' }, 400, headers);
      }
      const id = `fld_${randomHex(8)}`;
      const now = Date.now();
      await DB.prepare(`INSERT INTO items (id, type, name, created_at, parent_id) VALUES (?, 'folder', ?, ?, ?)`).bind(id, name, now, parentFolderId).run();
      return json({ success: true, id, name, parent_folder_id: parentFolderId }, 200, headers);
    }

    if (pathname === '/api/rename-folder' && request.method === 'POST') {
      const csrf = await requireCsrf(DB, request);
      if (!csrf.ok) return json(csrf.body, csrf.status, headers);
      const body = await readJsonOrForm(request);
      const id = body.id || body.folderId;
      const name = (body.name || body.newName || '').trim();
      if (!id || !name) return json({ error: 'id and name required' }, 400, headers);
      if (!(await DB.prepare(`SELECT id FROM items WHERE id = ? AND type = 'folder'`).bind(id).first('id'))) return json({ error: 'Folder not found' }, 404, headers);
      await DB.prepare(`UPDATE items SET name = ? WHERE id = ?`).bind(name, id).run();
      return json({ success: true }, 200, headers);
    }

    if (pathname === '/api/move' && request.method === 'POST') {
      const csrf = await requireCsrf(DB, request);
      if (!csrf.ok) return json(csrf.body, csrf.status, headers);
      const body = await readJsonOrForm(request);
      let targetFolderId = body.targetFolderId ?? body.destinationFolderId ?? null;
      if (targetFolderId === 'null' || targetFolderId === '') targetFolderId = null;
      let ids = body.ids;
      if (!Array.isArray(ids)) ids = ids ? [ids] : [];
      if (!ids.length) return json({ error: 'No items provided' }, 400, headers);

      if (targetFolderId) {
        if (!(await DB.prepare(`SELECT id FROM items WHERE id = ? AND type = 'folder'`).bind(targetFolderId).first('id'))) return json({ error: 'Target folder not found' }, 404, headers);
      }

      for (const id of ids) {
        const type = await DB.prepare(`SELECT type FROM items WHERE id = ?`).bind(id).first('type');
        if (!type) continue;
        
        if (id === targetFolderId) {
            return json({ error: 'Cannot move an item into itself.' }, 400, headers);
        }

        if (type === 'folder' && targetFolderId) {
          if (await isDescendant(DB, targetFolderId, id)) return json({ error: 'Cannot move a folder into its own descendant' }, 400, headers);
        }
        await DB.prepare(`UPDATE items SET parent_id = ? WHERE id = ?`).bind(targetFolderId, id).run();
      }
      return json({ success: true }, 200, headers);
    }

    if (pathname === '/api/delete' && request.method === 'POST') {
      const csrf = await requireCsrf(DB, request);
      if (!csrf.ok) return json(csrf.body, csrf.status, headers);
      const body = await readJsonOrForm(request);
      let ids = body.ids;
      if (!Array.isArray(ids)) ids = ids ? [ids] : [];
      if (!ids.length) return json({ error: 'No items provided' }, 400, headers);
      for (const id of ids) {
        const row = await DB.prepare(`SELECT id, type FROM items WHERE id = ?`).bind(id).first();
        if (!row) continue;
        if (row.type === 'folder') await deleteFolderRecursive(DB, id);
        else await DB.prepare(`DELETE FROM items WHERE id = ?`).bind(id).run();
      }
      return json({ success: true }, 200, headers);
    }

    if (pathname === '/api/folder-tree' && request.method === 'GET') {
      const auth = await requireAuth(DB, request);
      if (!auth.ok) return json(auth.body, 401, headers);
      const rows = (await DB.prepare(`SELECT id, name, parent_id FROM items WHERE type = 'folder'`).all()).results || [];
      return json(rows.map(r => ({ id: r.id, name: r.name, parent_folder_id: r.parent_id || null })), 200, headers);
    }

    if (pathname === '/api/shorten' && request.method === 'POST') {
      const csrf = await requireCsrf(DB, request);
      if (!csrf.ok) return json(csrf.body, csrf.status, headers);

      const body = await readJsonOrForm(request);
      const urlStr = (body.longUrl || body.url || body.originalUrl || '').trim();
      if (!urlStr) return json({ error: 'URL required' }, 400, headers);
      
      let urlObj;
      try {
        urlObj = new URL(urlStr);
      } catch {
        return json({ error: 'Invalid URL format' }, 400, headers);
      }
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return json({ error: 'Only http and https URLs are allowed' }, 400, headers);
      }

      let parentFolderId = body.parentFolderId ?? null;
      if (parentFolderId === 'null' || parentFolderId === '') {
        parentFolderId = null;
      }

      if (parentFolderId) {
        const exists = await DB.prepare(`SELECT id FROM items WHERE id = ? AND type = 'folder'`).bind(parentFolderId).first('id');
        if (!exists) return json({ error: 'Parent folder not found' }, 404, headers);
      }

      let key = normalizeKey(body.customKey || body.key || body.shortPath || '');
      if (!key) {
          key = randomHex(4);
      } else if (!KEY_RE.test(key)) {
          return json({ error: 'Invalid short path format. Use only letters, numbers, and hyphens.' }, 400, headers);
      }
      
      const existing = await DB.prepare(`SELECT id FROM items WHERE id = ?`).bind(key).first('id');
      if (existing) return json({ error: 'Key already exists' }, 409, headers);

      const now = Date.now();
      let passwordHash = null;
      if (body.password) {
        passwordHash = await hashPassword(body.password);
      }

      const maxClicks = body.maxClicks ? parseInt(body.maxClicks, 10) : null;
      const expiresAt = body.expiresAt ? parseInt(body.expiresAt, 10) : null;

      await DB.prepare(`INSERT INTO items (id, type, original_url, password_hash, max_clicks, clicks, expires_at, created_at, parent_id) VALUES (?, 'link', ?, ?, ?, 0, ?, ?, ?)`).bind(key, urlStr, passwordHash, maxClicks, expiresAt, now, parentFolderId).run();

      const fullShortUrl = new URL(key, `${url.origin}/`).toString();
      return json({ success: true, id: key, fullShortUrl }, 200, headers);
    }

    if (pathname === '/api/edit' && request.method === 'POST') {
      const csrf = await requireCsrf(DB, request);
      if (!csrf.ok) return json(csrf.body, csrf.status, headers);
      
      const body = await readJsonOrForm(request);
      const key = normalizeKey(body.key || body.id || '');
      if (!key) return json({ error: 'key required' }, 400, headers);
      
      const item = await DB.prepare(`SELECT id FROM items WHERE id = ? AND type = 'link'`).bind(key).first('id');
      if (!item) return json({ error: 'Link not found' }, 404, headers);

      const updates = [];
      const binds = [];

      const newKey = normalizeKey(body.newKey || body.shortPath || '');
      if (newKey && newKey !== key) {
          if (!KEY_RE.test(newKey)) {
              return json({ error: 'Invalid new short path format. Use only letters, numbers, and hyphens.' }, 400, headers);
          }
          const existing = await DB.prepare(`SELECT id FROM items WHERE id = ?`).bind(newKey).first('id');
          if (existing) {
              return json({ error: 'The new short path is already in use.' }, 409, headers);
          }
          updates.push('id = ?');
          binds.push(newKey);
      }

      if (body.longUrl) {
        const urlStr = body.longUrl.trim();
        let urlObj;
        try {
            urlObj = new URL(urlStr);
        } catch {
            return json({ error: 'Invalid URL format' }, 400, headers);
        }
        if (!['http:', 'https:'].includes(urlObj.protocol)) {
            return json({ error: 'Only http and https URLs are allowed' }, 400, headers);
        }
        updates.push('original_url = ?');
        binds.push(urlStr);
      }
      if ('maxClicks' in body) {
        updates.push('max_clicks = ?');
        binds.push(body.maxClicks ? parseInt(body.maxClicks, 10) : null);
      }
      if ('expiresAt' in body) {
        updates.push('expires_at = ?');
        binds.push(body.expiresAt ? parseInt(body.expiresAt, 10) : null);
      }
      if ('password' in body) {
        updates.push('password_hash = ?');
        binds.push(body.password ? await hashPassword(body.password) : null);
      }

      if (!updates.length) return json({ error: 'No changes' }, 400, headers);
      
      const sql = `UPDATE items SET ${updates.join(', ')} WHERE id = ?`;
      binds.push(key);
      await DB.prepare(sql).bind(...binds).run();

      const updatedKey = newKey || key;
      const fullShortUrl = new URL(updatedKey, `${url.origin}/`).toString();
      
      return json({ success: true, newKey: updatedKey, fullShortUrl }, 200, headers);
    }

    if (pathname.startsWith('/api/edit/') && request.method === 'GET') {
      const auth = await requireAuth(DB, request);
      if (!auth.ok) return json(auth.body, 401, headers);
      const key = normalizeKey(decodeURIComponent(pathname.slice('/api/edit/'.length)));
      const item = await DB.prepare(`SELECT original_url, max_clicks, expires_at, password_hash FROM items WHERE id = ? AND type = 'link'`).bind(key).first();
      if (!item) return json({ error: 'Link not found' }, 404, headers);
      return json({ url: item.original_url, maxClicks: item.max_clicks || 0, expiresAt: item.expires_at || null, hasPassword: !!item.password_hash }, 200, headers);
    }

    if (pathname === '/api/verify-link-password' && request.method === 'POST') {
      const body = await readJsonOrForm(request);
      const key = normalizeKey(body.key);
      const password = body.password || '';

      const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
      const rlKey = `link-pw:${ip}:${key}`;
      const now = Date.now();

      let attempts = 0, blockedUntil = 0, blockCount = 0;
      try {
        const rec = await DB.prepare(`SELECT attempts, blocked_until, block_count FROM login_attempts WHERE key = ?`).bind(rlKey).first();
        attempts = rec?.attempts || 0;
        blockedUntil = rec?.blocked_until || 0;
        blockCount = rec?.block_count || 0;
        if (blockedUntil && now < blockedUntil) {
          return json({ error: 'Too many attempts. Try again shortly.' }, 429, headers);
        }
      } catch (e) {}

      const item = await DB.prepare(`SELECT original_url, password_hash, max_clicks, clicks, expires_at FROM items WHERE id = ? AND type = 'link'`).bind(key).first();
      if (!item) return json({ error: 'Link not found' }, 404, headers);
      if (!item.password_hash) return json({ error: 'Link is not password protected' }, 400, headers);

      if (item.expires_at && now > item.expires_at) return json({ error: 'Link expired' }, 410, headers);
      if (item.max_clicks && (item.clicks || 0) >= item.max_clicks) return json({ error: 'Click limit reached' }, 410, headers);

      if (!(await verifyPassword(password, item.password_hash))) {
        try {
            attempts += 1;
            if (attempts % 5 === 0) {
              blockCount += 1;
              blockedUntil = now + Math.min(60_000 * Math.pow(2, blockCount -1), 10 * 60_000);
            }
            await DB.prepare(`INSERT INTO login_attempts (key, attempts, last_attempt_at, blocked_until, block_count) VALUES (?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET attempts=excluded.attempts, last_attempt_at=excluded.last_attempt_at, blocked_until=excluded.blocked_until, block_count=excluded.block_count`).bind(rlKey, attempts, now, blockedUntil, blockCount).run();
          } catch (e) {
            console.error("Failed to update rate-limit key:", e);
          }
        return json({ error: 'Incorrect password' }, 401, headers);
      }
      
      try {
          await DB.prepare(`DELETE FROM login_attempts WHERE key = ?`).bind(rlKey).run();
      } catch (e) {
          console.error("Failed to clear rate-limit key:", e);
      }

      await DB.prepare(`UPDATE items SET clicks = COALESCE(clicks,0) + 1 WHERE id = ?`).bind(key).run();
      return json({ success: true, redirectUrl: item.original_url }, 200, headers);
    }

    if (request.method === 'GET' && !pathname.startsWith('/api')) {
      const key = normalizeKey(pathname.slice(1));
      if (!key) {
        return styledMessageResponse('Nothing here. Use the admin UI.', 404, headers);
      }
      const item = await DB.prepare(`SELECT original_url, password_hash, max_clicks, clicks, expires_at FROM items WHERE id = ? AND type = 'link'`).bind(key).first();
      if (!item) {
        return styledMessageResponse('Short link not found.', 404, headers);
      }
      const now = Date.now();
      if (item.expires_at && now > item.expires_at) {
        return styledMessageResponse('This link has expired.', 410, headers);
      }
      if (item.max_clicks && (item.clicks || 0) >= item.max_clicks) {
        return styledMessageResponse('This link has reached its maximum clicks.', 410, headers);
      }
      if (item.password_hash) {
        const redirect = new URL('/password_protected.html', PAGES_BASE_URL);
        redirect.searchParams.set('key', key);
        return Response.redirect(redirect.toString(), 302);
      }
      await DB.prepare(`UPDATE items SET clicks = COALESCE(clicks,0) + 1 WHERE id = ?`).bind(key).run();
      const h = new Headers(headers);
      for (const [k, v] of Object.entries(noCache)) h.set(k, v);
      h.set('Location', item.original_url);
      return new Response('', { status: 302, headers: h });
    }

    return styledMessageResponse('Not found', 404, headers);
  }
};