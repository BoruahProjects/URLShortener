# URL Shortener (Cloudflare Pages + Workers + D1)

A **self‑hosted URL shortener** with:

- Custom short paths (e.g. `https://short.yourdomain.com/my-link`)
- Password‑protected links
- Folders (nesting, move, rename)
- Max‑clicks and expiry controls
- Admin dashboard with search, sort, filter & pagination
- Secure login, CSRF protection, and rate limiting

This project is designed to be hosted **for free** on **Cloudflare** using **Pages** (frontend) and **Workers** (backend API). Data is stored in **Cloudflare D1** (SQLite‑compatible). No third‑party services, no paid plans required for basic usage.

---

## Table of Contents
- [How it works](#how-it-works)
- [What you need](#what-you-need)
- [Project structure](#project-structure)
- [Step‑by‑step deployment (manual, no Wrangler)](#step-by-step-deployment-manual-no-wrangler)
  - [1) Create the Pages site (frontend)](#1-create-the-pages-site-frontend)
  - [2) Create the Worker (backend API)](#2-create-the-worker-backend-api)
  - [3) Create the D1 database and bind it](#3-create-the-d1-database-and-bind-it)
  - [4) Apply the database schema](#4-apply-the-database-schema)
  - [5) Set environment variables](#5-set-environment-variables)
  - [6) Point the frontend to the API](#6-point-the-frontend-to-the-api)
  - [7) (Optional) Custom domains / DNS](#7-optional-custom-domains--dns)
- [Generate admin username & password hashes](#generate-admin-username--password-hashes)
- [Using the dashboard](#using-the-dashboard)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [License](#license)

---

## How it works
- **Cloudflare Pages** serves the static files (dashboard, password gate page, styles, JS).
- **Cloudflare Worker** exposes the API under `/api/*` and handles redirects for short links.
- **Cloudflare D1** stores links, folders, sessions, and rate‑limit counters.
- Password‑protected links first send visitors to `password_protected.html`; after verification the user is redirected to the original URL.

---

## What you need
- A free **Cloudflare** account.
- (Optional) A domain on Cloudflare to host pretty URLs like `short.yourdomain.com` and `links.yourdomain.com`. You can also use the default `*.pages.dev` and `*.workers.dev` subdomains.

---

## Project structure
```
workers.js                 # Cloudflare Worker (backend API + redirect logic)
dashboard.js               # Admin dashboard logic
password-page.js           # Password gate page logic
password_protected.html    # Password entry page
index.html                 # Admin dashboard HTML
style.css                  # Styles for the whole UI
_headers                   # Security headers for Cloudflare Pages
generate-credentials.html  # Offline tool to create ADMIN_USER_HASH & ADMIN_PASS_PBKDF2
```

---

## Step‑by‑step deployment (manual, no Wrangler)

### 1) Create the Pages site (frontend)
1. Open **Cloudflare Dashboard → Pages → Create a project → Upload assets**.
2. Upload the frontend files:
   - `index.html`, `dashboard.js`, `password-page.js`, `password_protected.html`, `style.css`, `_headers`, `generate-credentials.html`.
3. Deploy. You’ll get a URL like `https://your-project.pages.dev`.
4. (Optional) Add a **custom domain**, e.g. `short.yourdomain.com`.

> The admin UI and password page will be served from **Pages**.

---

### 2) Create the Worker (backend API)
1. In **Workers & Pages → Create Application → Worker**.
2. Name it (e.g. `links-api`).
3. Paste the contents of **`workers.js`** into the editor.
4. Click **Deploy**.
5. You’ll get a URL like `https://links-api.your-subdomain.workers.dev`.
6. (Optional) Add a **custom domain**, e.g. `https://links.yourdomain.com`.

> The Worker hosts the API at `/api/*` and also handles public short‑link redirects.

---

### 3) Create the D1 database and bind it
1. Go to **Workers & Pages → D1 → Create Database** (name it e.g. `links-db`).
2. Open your Worker → **Settings → Variables & Bindings** → **D1 Databases** → **Add binding**.
3. **Binding name:** `DB`  
   **Database:** select your `links-db`.
4. Save and **Deploy** the Worker again if prompted.

---

### 4) Apply the database schema
Open the D1 database → **Console**, then run the following SQL (you can paste the entire block):

```sql
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS sessions (
  session_token TEXT PRIMARY KEY,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_attempt_at INTEGER NOT NULL,
  blocked_until INTEGER DEFAULT 0,
  block_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  type TEXT CHECK(type IN ('link','folder')) DEFAULT 'link',
  name TEXT,
  original_url TEXT,
  password_hash TEXT,
  max_clicks INTEGER,
  clicks INTEGER DEFAULT 0,
  expires_at INTEGER,
  created_at INTEGER,
  parent_id TEXT
);

ALTER TABLE items ADD COLUMN IF NOT EXISTS type TEXT CHECK(type IN ('link','folder')) DEFAULT 'link';
ALTER TABLE items ADD COLUMN IF NOT EXISTS parent_id TEXT;
ALTER TABLE items ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE items ADD COLUMN IF NOT EXISTS original_url TEXT;
ALTER TABLE items ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE items ADD COLUMN IF NOT EXISTS max_clicks INTEGER;
ALTER TABLE items ADD COLUMN IF NOT EXISTS clicks INTEGER DEFAULT 0;
ALTER TABLE items ADD COLUMN IF NOT EXISTS expires_at INTEGER;
ALTER TABLE items ADD COLUMN IF NOT EXISTS created_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_items_parent ON items(parent_id);
CREATE INDEX IF NOT EXISTS idx_items_type ON items(type);

COMMIT;
```

If your previous schema used different names (e.g., `url` instead of `original_url`), backfill as needed:
```sql
-- UPDATE items SET original_url = url    WHERE original_url IS NULL AND url    IS NOT NULL;
-- UPDATE items SET expires_at  = expiry WHERE expires_at  IS NULL AND expiry IS NOT NULL;
```

---

### 5) Set environment variables
Open your **Worker → Settings → Variables** and add:

| Name | Value |
|---|---|
| `ADMIN_USER_HASH` | **SHA‑256 hex** of your admin username (recommended). |
| `ADMIN_PASS_PBKDF2` | `pbkdf2:100000:<salt_hex>:<hash_hex>` for your admin password (required). |
| `PAGES_BASE_URL` | The origin of your Pages site (e.g., `https://short.yourdomain.com` or your `*.pages.dev`). |

> `ADMIN_USER_HASH` is optional in code: if not set, any username is accepted as long as the password matches. For best security, set it.

**CORS / allowed origins**  
The Worker enforces strict origins. In `workers.js` there is an **`allowed` array** (e.g., `['https://short.yourdomain.com']`). Update it to include your Pages host if you use custom or `*.pages.dev` URLs.

---

### 6) Point the frontend to the API
- In **`password-page.js`**, set:
  ```js
  const WORKER_API_URL = 'https://links.yourdomain.com';
  ```
  Replace with your Worker’s domain (or `*.workers.dev`).
- The HTML files include a CSP allowing `connect-src` to your API host. If you changed domains, update the `connect-src` value in the `<meta http-equiv="Content-Security-Policy">` tags in `index.html` and `password_protected.html`.

Re‑deploy the **Pages** project after any frontend changes.

---

### 7) (Optional) Custom domains / DNS
- **Pages**: map `short.yourdomain.com` to your Pages project.
- **Worker**: map `links.yourdomain.com` to your Worker (Routes or Custom Domain in the Worker settings).
- Ensure both are included in your CORS allowed list and CSP.

---

## Generate admin username & password hashes
You have two easy, offline options.

### Option A — Use `generate-credentials.html` (recommended)
1. Open `generate-credentials.html` in your browser (locally or from your deployed Pages site).
2. Enter your desired **username** and **password**.
3. Click **Generate**.
4. Copy the outputs into your Worker variables as:
   - `ADMIN_USER_HASH` ← SHA‑256 of username
   - `ADMIN_PASS_PBKDF2` ← `pbkdf2:100000:<salt_hex>:<hash_hex>`

### Option B — Use your browser console
```js
// 1) SHA-256 of username → ADMIN_USER_HASH
async function sha256(str){
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
sha256('your-username').then(console.log);

// 2) PBKDF2 of password → ADMIN_PASS_PBKDF2
async function pbkdf2(password, saltHex, iterations=100000, keyLen=32){
  const enc = new TextEncoder();
  const salt = Uint8Array.from(saltHex.match(/.{1,2}/g).map(h=>parseInt(h,16)));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, key, keyLen*8);
  const hex = [...new Uint8Array(bits)].map(b=>b.toString(16).padStart(2,'0')).join('');
  return hex;
}
(async()=>{
  const saltHex = [...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
  const hashHex = await pbkdf2('your-password', saltHex);
  console.log(`pbkdf2:100000:${saltHex}:${hashHex}`);
})();
```

---

## Using the dashboard
1. Visit your **Pages** site (e.g., `https://short.yourdomain.com`).
2. **Log in** with the username/password that match your configured hashes.
3. **Create a link**: click **Create Short URL**, paste the long URL, optionally set a custom short path, password, expiry, max clicks, and/or parent folder.
4. **Manage items**: use the table’s **sort**, **filter**, and **pagination**. Select multiple rows to **Move** or **Delete**.
5. **Edit** any link to change its path/URL/password/limits. Use the copy button to copy the short URL.

Visitors who open a **password‑protected** short link will be sent to the password page first; on success they’ll be redirected to the target URL.

---

## Troubleshooting
- **CORS error / blocked request**: ensure your Worker’s `allowed` origins include your Pages host, and that your HTML files’ CSP `connect-src` also lists your Worker domain.
- **401 / CSRF**: make sure you’re including credentials (`cookie`) on API calls. The provided dashboard does this automatically after login.
- **Login keeps failing**: verify the hashes. Regenerate with `generate-credentials.html` and update Worker variables.
- **Links not redirecting / 404**: confirm the key exists in `items`, not expired, and hasn’t hit `max_clicks`.
- **Password page loops**: ensure the `WORKER_API_URL` in `password-page.js` points to your Worker and that CSP allows it.

---

## Security notes
- Keep your **admin password** strong. Rotate it periodically and regenerate the PBKDF2 hash.
- Limit the **allowed origins** and ensure **CSP** is restrictive.
- D1 is production‑grade for small/medium workloads; back up regularly.

---

## License
This project is licensed under a custom license. Please refer to the `LICENSE` file for details.
