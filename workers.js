const SESSION_TOKEN_TTL_SECONDS = 3600;
const MAX_FOLDER_DEPTH = 10;
const MAX_ITEMS_PER_FOLDER = 500;
const MAX_PATH_LENGTH = 200;
const IDLE_SESSION_TIMEOUT_SECONDS = 10;

async function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const encoder = new TextEncoder();
    const aEncoded = encoder.encode(a);
    const bEncoded = encoder.encode(b);
    const aHashed = await crypto.subtle.digest('SHA-256', aEncoded);
    const bHashed = await crypto.subtle.digest('SHA-256', bEncoded);
    if (aHashed.byteLength !== bHashed.byteLength) return false;
    const aView = new Uint8Array(aHashed);
    const bView = new Uint8Array(bHashed);
    let diff = 0;
    for (let i = 0; i < aView.length; i++) {
        diff |= aView[i] ^ bView[i];
    }
    return diff === 0;
}

async function hash(input) {
  const msgUint8 = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(ip, db) {
    const key = `public:${ip}`;
    const windowSeconds = 60;
    const maxRequests = 10;
    const now = Date.now();
    const record = await db.prepare("SELECT timestamps FROM rate_limits WHERE key = ?").bind(key).first();
    let timestamps = record ? JSON.parse(record.timestamps) : [];
    const recentTimestamps = timestamps.filter(ts => (now - ts) < (windowSeconds * 1000));
    if (recentTimestamps.length >= maxRequests) return false;
    recentTimestamps.push(now);
    const newTimestamps = JSON.stringify(recentTimestamps);
    await db.prepare("INSERT INTO rate_limits (key, timestamps) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET timestamps = excluded.timestamps").bind(key, newTimestamps).run();
    return true;
}

async function getLoginBlockedUntil(key, db) {
    const record = await db.prepare("SELECT blocked_until FROM login_attempts WHERE key = ?").bind(key).first();
    if (record && record.blocked_until && Date.now() < record.blocked_until) {
        return record.blocked_until;
    }
    return null;
}

async function recordFailedLoginAttempt(key, db) {
    const MAX_LOGIN_ATTEMPTS = 5;
    const LOGIN_ATTEMPT_WINDOW_SECONDS = 600;

    const record = await db.prepare("SELECT attempts, last_attempt_timestamp, block_count FROM login_attempts WHERE key = ?").bind(key).first();
    const now = Date.now();
    let attempts = 1;
    let blockCount = 0;
    let blockedUntil = null;
    
    if (record) {
        blockCount = record.block_count;
        if (now - record.last_attempt_timestamp > LOGIN_ATTEMPT_WINDOW_SECONDS * 1000) {
            attempts = 1;
        } else {
            attempts = record.attempts + 1;
        }
    }
    
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
        const newBlockCount = blockCount + 1;
        const blockDurationSeconds = Math.min(3600, (LOGIN_ATTEMPT_WINDOW_SECONDS * Math.pow(2, newBlockCount - 1)));
        blockedUntil = now + (blockDurationSeconds * 1000);
        blockCount = newBlockCount;
    }

    await db.prepare(
        "INSERT INTO login_attempts (key, attempts, last_attempt_timestamp, blocked_until, block_count) VALUES (?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET attempts = excluded.attempts, last_attempt_timestamp = excluded.last_attempt_timestamp, blocked_until = excluded.blocked_until, block_count = excluded.block_count"
    ).bind(key, attempts, now, blockedUntil, blockCount).run();
}

async function resetLoginAttempts(key, db) {
    await db.prepare("DELETE FROM login_attempts WHERE key = ?").bind(key).run();
}

async function getFolderDepth(folderId, db) {
    if (!folderId) return 0;
    let depth = 0;
    let currentId = folderId;
    while (currentId && depth <= MAX_FOLDER_DEPTH + 1) {
        depth++;
        const parent = await db.prepare("SELECT parent_id FROM items WHERE id = ?").bind(currentId).first('parent_id');
        currentId = parent;
    }
    return depth;
}

async function isDescendant(itemId, potentialParentId, db) {
    let currentId = potentialParentId;
    while (currentId) {
        if (currentId === itemId) return true;
        currentId = await db.prepare("SELECT parent_id FROM items WHERE id = ?").bind(currentId).first('parent_id');
    }
    return false;
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const { pathname } = url;
        const DB = env.DB;
        const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';

        const commonHeaders = {
            'Access-Control-Allow-Origin': 'https://short.domain.com',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE, PUT',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
            'Access-Control-Allow-Credentials': 'true',
            'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        };

        const jsonResponse = (data, status = 200, additionalHeaders = {}) => new Response(JSON.stringify(data), {
            status, headers: { 'Content-Type': 'application/json', ...commonHeaders, ...additionalHeaders }
        });
        
        const styledMessageResponse = (message, status = 200) => new Response(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Notice</title><style>body{font-family: 'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#1e1e1e;color:#f5f5f5;margin:0;display:flex;justify-content:center;align-items:center;text-align:center;min-height:100vh;padding:1rem;box-sizing:border-box;}.message-container{max-width:600px}</style></head><body><div class="message-container"><h2>${message}</h2></div></body></html>`, {
            status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate', 'Referrer-Policy': 'no-referrer', ...commonHeaders }
        });
        
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: { ...commonHeaders, 'Access-Control-Max-Age': '86400' } });
        }

        if (pathname.startsWith('/api/')) {
            return handleApiRequest(request, env);
        }

        const isAllowed = await checkRateLimit(clientIp, DB);
        if (!isAllowed) {
            return styledMessageResponse('You are making too many requests. Please try again in a moment.', 429);
        }

        const key = pathname.slice(1);
        const item = await DB.prepare("SELECT * FROM items WHERE id = ? AND type = 'link'").bind(key).first();

        if (!item) return styledMessageResponse('Resource not found.', 404);

        const now = Date.now();
        const noCacheHeaders = { 'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate', 'Referrer-Policy': 'no-referrer' };

        if (item.expires_at && item.expires_at < now) return styledMessageResponse('This link has expired.', 410);
        if (item.max_clicks > 0 && item.clicks >= item.max_clicks) return styledMessageResponse('This link has reached its maximum click limit.', 410);

        if (!item.password_hash) {
            await DB.prepare("UPDATE items SET clicks = clicks + 1 WHERE id = ?").bind(key).run();
            return new Response(null, { status: 302, headers: { ...noCacheHeaders, 'Location': item.original_url } });
        }

        if (request.method === 'GET') {
            const redirectUrl = `https://short.domain.com/password_protected.html?key=${key}`;
            return Response.redirect(redirectUrl, 302);
        }

        if (request.method === 'POST') {
            const form = await request.formData();
            const password = form.get('password');
            if (await timingSafeEqual(await hash(password), item.password_hash)) {
                await DB.prepare("UPDATE items SET clicks = clicks + 1 WHERE id = ?").bind(key).run();
                return jsonResponse({ success: true, redirectUrl: item.original_url });
            }
            return jsonResponse({ error: 'Authentication failed.' }, 403);
        }

        return jsonResponse({ error: 'Method not allowed.' }, 405);


        async function handleApiRequest(request, env) {
            const url = new URL(request.url);
            const { pathname } = url;
            const DB = env.DB;
            const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';

            const isAuthenticated = async (currentClientIp) => {
                const cookieHeader = request.headers.get("Cookie");
                if (!cookieHeader) return { valid: false, reason: 'no_token', token: null, sessionIp: null };
                const cookieMatch = cookieHeader.match(/auth_token=([^;]+)/);
                if (!cookieMatch) return { valid: false, reason: 'no_token', token: null, sessionIp: null };
                const token = cookieMatch[1];
                
                const session = await DB.prepare("SELECT session_token, last_activity_at, expires_at, ip_address FROM sessions WHERE session_token = ? AND expires_at > ?").bind(token, Date.now()).first();
                
                if (!session) return { valid: false, reason: 'invalid_token', token: null, sessionIp: null };

                const now = Date.now();

                if (now - session.last_activity_at > IDLE_SESSION_TIMEOUT_SECONDS * 1000) {
                    await DB.prepare("DELETE FROM sessions WHERE session_token = ?").bind(token).run();
                    await DB.prepare("DELETE FROM admin_session WHERE id = 1").run();
                    return { valid: false, reason: 'idle_timeout', token: null, sessionIp: null };
                }
                
                await DB.prepare("UPDATE sessions SET last_activity_at = ? WHERE session_token = ?").bind(now, token).run();

                return { valid: true, token, sessionIp: session.ip_address };
            };

            const isCsrfTokenValid = async (authResult) => {
                if (!authResult.valid) return false;
                const headerToken = request.headers.get('X-CSRF-Token');
                if (!headerToken) return false;
                const session = await DB.prepare("SELECT csrf_token_hash FROM sessions WHERE session_token = ?").bind(authResult.token).first();
                if (!session) return false;
                return await timingSafeEqual(await hash(headerToken), session.csrf_token_hash);
            };

            if (pathname === '/api/check-auth') {
                const authResult = await isAuthenticated(clientIp);
                return jsonResponse({ authenticated: authResult.valid }, authResult.valid ? 200 : 401);
            }

            if (pathname === '/api/login') {
                const ipKey = `ip:${clientIp}`;
                const ipBlockedUntil = await getLoginBlockedUntil(ipKey, DB);
                if (ipBlockedUntil) return jsonResponse({ error: 'Too many failed login attempts. Please try again later.' }, 429);
                
                const form = await request.formData();
                const username = form.get('username');
                const password = form.get('password');
                const usernameKey = `username:${username}`;

                const usernameBlockedUntil = await getLoginBlockedUntil(usernameKey, DB);
                if (usernameBlockedUntil) {
                     await recordFailedLoginAttempt(ipKey, DB);
                     return jsonResponse({ error: 'Authentication failed for this user.' }, 403);
                }

                const isUsernameValid = await timingSafeEqual(await hash(username), env.ADMIN_USERNAME_HASH);
                const isPasswordValid = await timingSafeEqual(await hash(password), env.ADMIN_PASSWORD_HASH);
    
                if (isUsernameValid && isPasswordValid) {
                    await Promise.all([resetLoginAttempts(ipKey, DB), resetLoginAttempts(usernameKey, DB)]);

                    const oldAdminSession = await DB.prepare("SELECT session_token FROM admin_session WHERE id = 1").first();
                    if(oldAdminSession) {
                        await DB.prepare("DELETE FROM sessions WHERE session_token = ?").bind(oldAdminSession.session_token).run();
                    }

                    const newSessionToken = crypto.randomUUID();
                    const newCsrfToken = crypto.randomUUID();
                    const csrfTokenHash = await hash(newCsrfToken);
                    const now = Date.now();
                    const expiresAt = now + (SESSION_TOKEN_TTL_SECONDS * 1000);

                    await DB.batch([
                        DB.prepare("INSERT INTO sessions (session_token, csrf_token_hash, created_at, expires_at, last_activity_at, ip_address) VALUES (?, ?, ?, ?, ?, ?)").bind(newSessionToken, csrfTokenHash, now, expiresAt, now, clientIp),
                        DB.prepare("INSERT INTO admin_session (id, session_token) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET session_token = excluded.session_token").bind(newSessionToken)
                    ]);
    
                    const sessionCookie = `auth_token=${newSessionToken}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${SESSION_TOKEN_TTL_SECONDS}`;
                    const response = jsonResponse({ success: true, csrfToken: newCsrfToken });
                    response.headers.append('Set-Cookie', sessionCookie);
                    return response;
                } else {
                    await Promise.all([recordFailedLoginAttempt(ipKey, DB), recordFailedLoginAttempt(usernameKey, DB)]);
                    return jsonResponse({ error: 'Invalid username or password.' }, 403);
                }
            }

            const authResult = await isAuthenticated(clientIp);
            if (!authResult.valid) return jsonResponse({ error: 'Authentication required.', reason: authResult.reason }, 401);

            if (authResult.sessionIp && authResult.sessionIp !== clientIp) {
                await DB.prepare("DELETE FROM sessions WHERE session_token = ?").bind(authResult.token).run();
                await DB.prepare("DELETE FROM admin_session WHERE id = 1").run();
                return jsonResponse({ error: 'Session IP mismatch. Please log in again.' }, 401);
            }

            if (pathname === '/api/logout') {
                await DB.batch([
                    DB.prepare("DELETE FROM sessions WHERE session_token = ?").bind(authResult.token),
                    DB.prepare("DELETE FROM admin_session WHERE id = 1")
                ]);
                const response = jsonResponse({ success: true });
                response.headers.append('Set-Cookie', 'auth_token=; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=0');
                return response;
            }
            
            if (pathname === '/api/session-info') {
                const newCsrfToken = crypto.randomUUID();
                await DB.prepare("UPDATE sessions SET csrf_token_hash = ? WHERE session_token = ?").bind(await hash(newCsrfToken), authResult.token).run();
                return jsonResponse({ csrfToken: newCsrfToken });
            }

            if (!await isCsrfTokenValid(authResult)) return jsonResponse({ error: 'Invalid security token.' }, 403);

            if (pathname === '/api/admin') {
                let query = "SELECT * FROM items";
                let countQuery = "SELECT count(*) as total FROM items";
                let whereClauses = [];
                let bindings = [];

                const parentFolderId = url.searchParams.get('folderId');
                if (parentFolderId === 'null') {
                    whereClauses.push("parent_id IS NULL");
                } else if (parentFolderId) {
                    whereClauses.push("parent_id = ?");
                    bindings.push(parentFolderId);
                }

                const searchQuery = url.searchParams.get('search')?.toLowerCase();
                if (searchQuery) {
                    whereClauses.push("( (type = 'folder' AND name LIKE ?) OR (type = 'link' AND (id LIKE ? OR original_url LIKE ?)) )");
                    const searchTerm = `%${searchQuery}%`;
                    bindings.push(searchTerm, searchTerm, searchTerm);
                }

                const minClicks = parseInt(url.searchParams.get('minClicks'), 10);
                if (!isNaN(minClicks)) {
                    whereClauses.push("clicks >= ?");
                    bindings.push(minClicks);
                }
                const maxClicks = parseInt(url.searchParams.get('maxClicks'), 10);
                if (!isNaN(maxClicks)) {
                    whereClauses.push("clicks <= ?");
                    bindings.push(maxClicks);
                }

                const expiryStatus = url.searchParams.get('expiryStatus');
                if (expiryStatus && expiryStatus !== 'all') {
                    const now = Date.now();
                    if (expiryStatus === 'never') {
                        whereClauses.push("expires_at IS NULL");
                    } else if (expiryStatus === 'expired') {
                        whereClauses.push("expires_at IS NOT NULL AND expires_at < ?");
                        bindings.push(now);
                    } else if (expiryStatus === 'expiresSoon') {
                        whereClauses.push("expires_at BETWEEN ? AND ?");
                        bindings.push(now, now + 86400000);
                    }
                }

                const creationDateFrom = parseInt(url.searchParams.get('creationDateFrom'), 10);
                if (!isNaN(creationDateFrom)) {
                    whereClauses.push("created_at >= ?");
                    bindings.push(creationDateFrom);
                }
                const creationDateTo = parseInt(url.searchParams.get('creationDateTo'), 10);
                if (!isNaN(creationDateTo)) {
                    whereClauses.push("created_at <= ?");
                    bindings.push(creationDateTo);
                }

                if (whereClauses.length > 0) {
                    const finalWhere = `WHERE ${whereClauses.join(' AND ')}`;
                    query += ` ${finalWhere}`;
                    countQuery += ` ${finalWhere}`;
                }

                let sortBy = url.searchParams.get('sortBy') || 'created_at';
                let sortOrder = url.searchParams.get('sortOrder') || 'DESC';
                const allowedSortBy = ['created_at', 'clicks', 'id'];
                if (!allowedSortBy.includes(sortBy)) {
                    sortBy = 'created_at';
                }
                if (sortOrder.toUpperCase() !== 'ASC' && sortOrder.toUpperCase() !== 'DESC') {
                    sortOrder = 'DESC';
                }
                
                const page = parseInt(url.searchParams.get("page") || "1");
                const itemsPerPage = 10;
                query += ` ORDER BY type ASC, ${sortBy} ${sortOrder} LIMIT ? OFFSET ?`;
                
                const itemsPromise = DB.prepare(query).bind(...bindings, itemsPerPage, (page - 1) * itemsPerPage).all();
                const totalPromise = DB.prepare(countQuery).bind(...bindings).first('total');
                
                const [{ results }, totalItems] = await Promise.all([itemsPromise, totalPromise]);

                const formattedItems = results.map(item => ({
                    id: item.id, key: item.id, is_folder: item.type === 'folder', name: item.name,
                    fullShortUrl: item.type === 'link' ? new URL(item.id, 'https://links.domain.com').toString() : null,
                    originalUrl: item.original_url, hasPassword: !!item.password_hash, clicks: item.clicks,
                    maxClicks: item.max_clicks, expirationTimestamp: item.expires_at, created: item.created_at
                }));
                return jsonResponse({ items: formattedItems, page, totalPages: Math.ceil(totalItems / itemsPerPage) });
            }

            if (pathname === '/api/create-folder') {
                const { folderName, parentFolderId } = await request.json();
                if (typeof folderName !== 'string' || !folderName.trim() || folderName.length > 100 || !/^[a-zA-Z0-9\s\-_.,()]+$/.test(folderName)) {
                    return jsonResponse({ error: 'Invalid folder name.' }, 400);
                }

                const parentId = parentFolderId === 'null' ? null : parentFolderId;
                const depth = await getFolderDepth(parentId, DB);
                if (depth >= MAX_FOLDER_DEPTH) return jsonResponse({ error: `Maximum folder depth of ${MAX_FOLDER_DEPTH} reached.` }, 400);

                const { count } = await DB.prepare("SELECT count(*) as count FROM items WHERE parent_id " + (parentId ? "= ?" : "IS NULL")).bind(...(parentId ? [parentId] : [])).first();
                if (count >= MAX_ITEMS_PER_FOLDER) return jsonResponse({ error: `A folder cannot contain more than ${MAX_ITEMS_PER_FOLDER} items.` }, 400);

                const id = crypto.randomUUID();
                await DB.prepare("INSERT INTO items (id, type, name, created_at, parent_id) VALUES (?, 'folder', ?, ?, ?)").bind(id, folderName, Date.now(), parentId).run();
                return jsonResponse({ success: true, id });
            }
            
            if (pathname === '/api/rename-folder') {
                const { folderId, newName } = await request.json();
                if (!folderId || typeof newName !== 'string' || !newName.trim() || newName.length > 100 || !/^[a-zA-Z0-9\s\-_.,()]+$/.test(newName)) {
                    return jsonResponse({ error: 'Invalid folder name provided.' }, 400);
                }
                await DB.prepare("UPDATE items SET name = ? WHERE id = ? AND type = 'folder'").bind(newName.trim(), folderId).run();
                return jsonResponse({ success: true });
            }

            if (pathname === '/api/shorten') {
                const form = await request.formData();
                const longUrl = form.get('longUrl');
                const shortPath = form.get('shortPath');
                if (typeof longUrl !== 'string' || typeof shortPath !== 'string' || !longUrl.trim() || !shortPath.trim() || shortPath.length > MAX_PATH_LENGTH) return jsonResponse({ error: 'Invalid input.' }, 400);

                const existing = await DB.prepare("SELECT id FROM items WHERE id = ?").bind(shortPath).first();
                if (existing) return jsonResponse({ error: 'Path already exists.' }, 409);
                
                const parentFolderId = form.get('parentFolderId') === 'null' ? null : form.get('parentFolderId');
                const { count } = await DB.prepare("SELECT count(*) as count FROM items WHERE parent_id " + (parentFolderId ? "= ?" : "IS NULL")).bind(...(parentFolderId ? [parentFolderId] : [])).first();
                if (count >= MAX_ITEMS_PER_FOLDER) return jsonResponse({ error: `A folder cannot contain more than ${MAX_ITEMS_PER_FOLDER} items.` }, 400);

                const password = form.get('password');
                await DB.prepare("INSERT INTO items (id, type, original_url, password_hash, max_clicks, expires_at, created_at, parent_id) VALUES (?, 'link', ?, ?, ?, ?, ?, ?)")
                   .bind(shortPath, longUrl, password ? await hash(password) : null, parseInt(form.get('maxClicks'), 10) || 0, parseInt(form.get('expiresAtTimestamp'), 10) || null, Date.now(), parentFolderId)
                   .run();
                return jsonResponse({ success: true, shortUrl: new URL(shortPath, 'https://links.domain.com').toString() });
            }
            
            if (pathname === '/api/delete') {
                const { ids } = await request.json();
                if (!Array.isArray(ids)) return jsonResponse({ error: 'Invalid request' }, 400);
                const placeholders = ids.map(() => '?').join(',');
                await DB.prepare(`DELETE FROM items WHERE id IN (${placeholders})`).bind(...ids).run();
                return jsonResponse({ success: true, deletedCount: ids.length });
            }
            
            if (pathname === '/api/move') {
                const { ids, destinationFolderId } = await request.json();
                if (!Array.isArray(ids)) return jsonResponse({ error: 'Invalid request' }, 400);
                const destId = destinationFolderId === 'null' ? null : destinationFolderId;
                for (const id of ids) {
                    if (id === destId || await isDescendant(id, destId, DB)) {
                        return jsonResponse({ error: 'Cannot move a folder into itself or one of its children.' }, 400);
                    }
                }
                const placeholders = ids.map(() => '?').join(',');
                await DB.prepare(`UPDATE items SET parent_id = ? WHERE id IN (${placeholders})`).bind(destId, ...ids).run();
                return jsonResponse({ success: true });
            }

            if (pathname === '/api/folder-tree') {
                const { results } = await DB.prepare("SELECT id, name, parent_id FROM items WHERE type = 'folder'").all();
                return jsonResponse(results.map(r => ({ id: r.id, name: r.name, parent_folder_id: r.parent_id })));
            }
            
            if (pathname.startsWith('/api/edit/')) {
                const item = await DB.prepare("SELECT original_url, expires_at, max_clicks, password_hash FROM items WHERE id = ?").bind(pathname.split('/').pop()).first();
                if (!item) return jsonResponse({ error: 'Resource not found' }, 404);
                return jsonResponse({ url: item.original_url, expiresAt: item.expires_at, maxClicks: item.max_clicks, hasPassword: !!item.password_hash });
            }

            if (pathname === '/api/edit') {
                 const form = await request.formData();
                 const originalKey = form.get('originalKey');
                 const newKey = form.get('newKey');
                 if (originalKey !== newKey) {
                     const existing = await DB.prepare("SELECT id FROM items WHERE id = ?").bind(newKey).first();
                     if (existing) return jsonResponse({ error: 'New path is already in use.' }, 409);
                 }

                 let passwordHash = undefined;
                 if (form.has('password')) {
                     const password = form.get('password');
                     passwordHash = password ? await hash(password) : "";
                 }

                 let bindings = [form.get('longUrl'), parseInt(form.get('expiresAtTimestamp'), 10) || null, parseInt(form.get('maxClicks'), 10) || 0];
                 let query = "UPDATE items SET original_url = ?, expires_at = ?, max_clicks = ?";
                 if(passwordHash !== undefined) {
                     query += ", password_hash = ?";
                     bindings.push(passwordHash);
                 }
                 if (originalKey !== newKey) {
                    query += ", id = ?";
                    bindings.push(newKey);
                 }
                 query += " WHERE id = ?";
                 bindings.push(originalKey);
                 
                 await DB.prepare(query).bind(...bindings).run();

                 if (originalKey !== newKey) {
                    await DB.prepare("UPDATE items SET parent_id = ? WHERE parent_id = ?").bind(newKey, originalKey).run();
                 }
                 return jsonResponse({ success: true });
            }

            return jsonResponse({ error: 'API endpoint not found.' }, 404);
        }
    }
};