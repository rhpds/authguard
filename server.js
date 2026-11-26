'use strict';

/**
 * authguard - a tiny, dependency-free ForwardAuth service for Traefik.
 *
 * Gives every route behind the proxy a single shared "deploy-time" token,
 * exchanged for a signed, expiring cookie so the browser doesn't need to
 * keep passing the token after the first successful hit.
 *
 * Routes:
 *   GET  /verify  - called internally by Traefik's forwardAuth middleware
 *   GET  /login   - renders the token entry form
 *   POST /login   - validates the submitted token, sets the cookie, redirects
 *
 * No database, no user management, no session store - just an HMAC-signed
 * cookie value. See docs/showroom-architecture.md style conventions are not
 * required here; this is intentionally self-contained.
 */

const http = require('http');
const crypto = require('crypto');
const querystring = require('querystring');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8080);
const AUTH_TOKEN = process.env.AUTH_TOKEN;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 43200); // 12h default
const COOKIE_NAME = 'nookbag_auth';
const LOGIN_PATH = '/login';

// Failed-token-attempt rate limiting - see "Rate limiting" section below.
const RATE_LIMIT_MAX_ATTEMPTS = Number(process.env.RATE_LIMIT_MAX_ATTEMPTS || 10);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_SECONDS || 60) * 1000;
const RATE_LIMIT_LOCKOUT_MS = Number(process.env.RATE_LIMIT_LOCKOUT_SECONDS || 300) * 1000;

if (!AUTH_TOKEN) {
  console.error('authguard: AUTH_TOKEN env var is required');
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.error('authguard: SESSION_SECRET env var is required');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Cookie signing (stateless, HMAC-SHA256 over an expiry timestamp)
// ---------------------------------------------------------------------------

function sign(expiryMs) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(String(expiryMs)).digest('hex');
}

function makeSessionCookieValue() {
  const expiryMs = Date.now() + SESSION_TTL_SECONDS * 1000;
  return `${expiryMs}.${sign(expiryMs)}`;
}

function constantTimeEquals(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    // Still run a timingSafeEqual against a same-length buffer so the
    // comparison cost doesn't trivially leak length information either.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function isValidSessionCookie(value) {
  if (!value) return false;
  const dotIndex = value.indexOf('.');
  if (dotIndex === -1) return false;
  const expiryStr = value.slice(0, dotIndex);
  const mac = value.slice(dotIndex + 1);
  const expiryMs = Number(expiryStr);
  if (!Number.isFinite(expiryMs)) return false;
  if (!constantTimeEquals(mac, sign(expiryMs))) return false;
  return expiryMs > Date.now();
}

function isValidToken(candidate) {
  if (!candidate) return false;
  return constantTimeEquals(candidate, AUTH_TOKEN);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  }
  return out;
}

function sessionCookieHeader(value, proto) {
  const parts = [
    `${COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ];
  if (proto === 'https') parts.push('Secure');
  return parts.join('; ');
}

// Only allow same-origin, relative redirect targets (no scheme/host) to
// avoid turning the login form into an open redirector.
function sanitizeRedirectTarget(rd) {
  if (!rd || typeof rd !== 'string') return '/';
  if (!rd.startsWith('/')) return '/';
  if (rd.startsWith('//')) return '/';
  if (rd.includes('://')) return '/';
  // Many browsers normalize a leading "\" the same as "/" when resolving a
  // URL, so "/\evil.com" (or "/\/evil.com") would otherwise slip past the
  // "//" check above and resolve to a scheme-relative URL pointing at an
  // attacker-controlled host. Reject any backslash outright instead of
  // trying to enumerate every normalization quirk.
  if (rd.includes('\\')) return '/';
  return rd;
}

// Strips the one-time `token` query param out of a forwarded URI before
// it's used as a redirect target. A token-in-URL login (see handleVerify)
// shouldn't leave that token sitting in the browser's address bar,
// history, or a Referer header any longer than the single request that
// redeemed it. Also runs the result through sanitizeRedirectTarget so a
// forged X-Forwarded-Uri (trustForwardHeader: true - see AGENTS.md "Known
// Gotchas") still can't turn this into an open redirect.
function cleanRedirectTarget(forwardedUri) {
  if (!forwardedUri || typeof forwardedUri !== 'string') return '/';
  let parsed;
  try {
    parsed = new URL(forwardedUri, 'http://placeholder');
  } catch (_err) {
    return '/';
  }
  parsed.searchParams.delete('token');
  return sanitizeRedirectTarget(parsed.pathname + parsed.search);
}

function readBody(req, maxBytes = 8192) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

// querystring.parse() returns an array (not a string) when a key appears
// more than once, e.g. "token=a&token=b" -> { token: ['a', 'b'] }. Collapse
// to the first value so callers can keep assuming a string instead of
// silently stringifying an array (Buffer.from(String(['a','b']))) or
// throwing out of a string-only helper.
function firstValue(value) {
  return Array.isArray(value) ? value[0] : value;
}

// Node joins a header that was sent multiple times into a single
// comma-separated string (e.g. "https, http"), which would otherwise fail
// the strict "=== 'https'" check in sessionCookieHeader() and silently
// skip the Secure cookie flag. Take the first value, same as a browser
// would for a duplicated header.
function firstHeaderValue(value) {
  if (!value) return value;
  return String(value).split(',')[0].trim();
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

function renderLoginPage({ rd, error, rateLimited }) {
  const safeRd = escapeHtml(sanitizeRedirectTarget(rd));
  let errorBanner = '';
  if (rateLimited) {
    errorBanner = '<p class="error">Too many attempts. Please wait a few minutes and try again.</p>';
  } else if (error) {
    errorBanner = '<p class="error">Invalid token. Please try again.</p>';
  }
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sign in</title>
  <link rel="icon" type="image/svg+xml" href="https://demo.redhat.com/images/favicon.ico">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; background: #F2F2F2; color: #151515; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .logo { width: 280px; max-width: 70vw; margin-bottom: 2rem; }
    .card { background: #fff; padding: 2rem 2.5rem; border-radius: 0.5rem; box-shadow: 0 2px 10px rgba(0,0,0,0.12); width: 100%; max-width: 320px; box-sizing: border-box; }
    h1 { font-size: 1.25rem; margin: 0 0 1rem; color: #151515; }
    input[type="password"], input[type="text"] { width: 100%; padding: 0.6rem 0.75rem; margin: 0.5rem 0 1rem; border-radius: 0.375rem; border: 1px solid #d2d2d2; background: #fff; color: #151515; box-sizing: border-box; }
    button { width: 100%; padding: 0.6rem 0.75rem; border-radius: 0.375rem; border: none; background: #0066cc; color: white; font-weight: 600; cursor: pointer; }
    button:hover { background: #004d99; }
    .error { color: #c9190b; font-size: 0.9rem; margin: 0 0 0.75rem; }
  </style>
</head>
<body>
  <svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1300 178.739"><g fill="#151515"><path d="M316.6 63.2v-56H342a21.279 21.279 0 0 1 7.8 1.3 18.111 18.111 0 0 1 5.9 3.5 15.577 15.577 0 0 1 5 11.8 15.051 15.051 0 0 1-3.1 9.5 16.836 16.836 0 0 1-8.4 5.8l12.5 24.1h-9.3l-11.6-23H325v23Zm24.7-48.6H325v18.7h16.3q5.25 0 8.1-2.7a8.7 8.7 0 0 0 2.8-6.6 8.7 8.7 0 0 0-2.8-6.6c-1.8-1.9-4.5-2.8-8.1-2.8ZM364.1 42.8a20.674 20.674 0 0 1 1.6-8.2 20.288 20.288 0 0 1 4.3-6.7 19.92 19.92 0 0 1 6.5-4.5 19.718 19.718 0 0 1 8-1.6 18.463 18.463 0 0 1 7.8 1.6 18.677 18.677 0 0 1 6.2 4.5 20.927 20.927 0 0 1 4.1 6.8 23.2 23.2 0 0 1 1.5 8.4v2.3H372a13.822 13.822 0 0 0 4.6 8.4 13.6 13.6 0 0 0 9.1 3.3 15.553 15.553 0 0 0 5.7-1 12.858 12.858 0 0 0 4.6-2.6l5.1 5a25.983 25.983 0 0 1-7.4 4.1 24.69 24.69 0 0 1-8.4 1.3 21.306 21.306 0 0 1-8.4-1.6 22.763 22.763 0 0 1-6.8-4.4 20.788 20.788 0 0 1-4.5-6.7 23.2 23.2 0 0 1-1.5-8.4Zm20.2-14.2a11.527 11.527 0 0 0-8 3 13.046 13.046 0 0 0-4.2 7.8h24.2a13.091 13.091 0 0 0-4.2-7.8 11.106 11.106 0 0 0-7.8-3ZM443.1 63.2v-3.8a19.448 19.448 0 0 1-5.8 3.3 18.924 18.924 0 0 1-6.7 1.2 19.824 19.824 0 0 1-14.6-6.1 22.268 22.268 0 0 1-4.4-6.7 21.812 21.812 0 0 1 0-16.4A20.534 20.534 0 0 1 416 28a19.335 19.335 0 0 1 6.6-4.5 20.334 20.334 0 0 1 8.2-1.6 20.7 20.7 0 0 1 6.6 1 19.415 19.415 0 0 1 5.7 3V7.2l8-1.8v57.8Zm-25.2-20.4a13.718 13.718 0 0 0 4 10.1 13.45 13.45 0 0 0 9.8 4.1 14.956 14.956 0 0 0 6.4-1.3 15.954 15.954 0 0 0 4.9-3.6V33.6a14.988 14.988 0 0 0-4.9-3.5 15.271 15.271 0 0 0-6.4-1.3 13.423 13.423 0 0 0-9.9 4 13.806 13.806 0 0 0-3.9 10ZM478.1 63.2v-56h8.4v24h29.8v-24h8.4v56h-8.4V38.8h-29.8v24.4ZM547.2 64a16.483 16.483 0 0 1-10.8-3.5 11.037 11.037 0 0 1-4.2-8.9 10.375 10.375 0 0 1 4.7-9.2 20.76 20.76 0 0 1 11.8-3.2 27.841 27.841 0 0 1 5.8.6 27.374 27.374 0 0 1 5.3 1.6v-4.3a8.143 8.143 0 0 0-2.6-6.5 11.452 11.452 0 0 0-7.4-2.2 20.788 20.788 0 0 0-6 .9 34.616 34.616 0 0 0-6.6 2.6l-3-6a54.169 54.169 0 0 1 8.4-3.1 33.18 33.18 0 0 1 8.3-1.1c5.2 0 9.3 1.3 12.2 3.8s4.4 6.1 4.4 10.8v27h-7.8v-3.5a19.441 19.441 0 0 1-5.8 3.2 23.54 23.54 0 0 1-6.7 1Zm-7.3-12.6a5.646 5.646 0 0 0 2.6 4.8 11.193 11.193 0 0 0 6.6 1.8 16.256 16.256 0 0 0 5.9-1 14.449 14.449 0 0 0 4.9-2.9V47a19.778 19.778 0 0 0-4.8-1.8 24.933 24.933 0 0 0-5.7-.6 11.859 11.859 0 0 0-6.8 1.8 5.728 5.728 0 0 0-2.7 5ZM580.6 53.2v-24H572v-6.7h8.6V12.1l7.9-1.9v12.3h12v6.7h-12v22.1a5.94 5.94 0 0 0 1.4 4.4c.9.9 2.5 1.3 4.6 1.3a23.637 23.637 0 0 0 3-.2 10.857 10.857 0 0 0 2.8-.8v6.7a19.28 19.28 0 0 1-3.8.9 27.484 27.484 0 0 1-3.8.3c-3.9 0-7-.9-9-2.8-2-1.7-3.1-4.4-3.1-7.9Z"/></g><path d="M127 90.2c12.5 0 30.6-2.6 30.6-17.5a12.678 12.678 0 0 0-.3-3.4L149.8 37c-1.7-7.1-3.2-10.3-15.7-16.6-9.7-5-30.8-13.1-37.1-13.1-5.8 0-7.5 7.5-14.4 7.5-6.7 0-11.6-5.6-17.9-5.6-6 0-9.9 4.1-12.9 12.5 0 0-8.4 23.7-9.5 27.2a4.216 4.216 0 0 0-.3 1.9c0 9.2 36.3 39.4 85 39.4Zm32.5-11.4c1.7 8.2 1.7 9.1 1.7 10.1 0 14-15.7 21.8-36.4 21.8-46.8 0-87.7-27.4-87.7-45.5a17.535 17.535 0 0 1 1.5-7.3C21.8 58.8 0 61.8 0 81c0 31.5 74.6 70.3 133.7 70.3 45.3 0 56.7-20.5 56.7-36.6-.1-12.8-11-27.3-30.9-35.9Z" fill="#e00"/><path d="M159.5 78.8c1.7 8.2 1.7 9.1 1.7 10.1 0 14-15.7 21.8-36.4 21.8-46.8 0-87.7-27.4-87.7-45.5a17.535 17.535 0 0 1 1.5-7.3l3.7-9.1a4.877 4.877 0 0 0-.3 2c0 9.2 36.3 39.4 85 39.4 12.5 0 30.6-2.6 30.6-17.5a12.678 12.678 0 0 0-.3-3.4Z"/><path d="M253.5 158.7a2.22 2.22 0 0 1-2.2-2.2V2.2a2.2 2.2 0 0 1 4.4 0v154.2a2.242 2.242 0 0 1-2.2 2.3Z" fill="#151515"/><text data-name="Demo Platform" transform="translate(1186 149)" fill="#151515" font-size="82" font-family="'RedHatDisplay', 'Overpass', overpass, helvetica, arial, sans-serif" font-weight="700"><tspan x="-877.892" y="0">Demo Platform</tspan></text></svg>
  <div class="card">
    <h1>Enter access token</h1>
    ${errorBanner}
    <form method="POST" action="/login">
      <input type="password" name="token" placeholder="Access token" autofocus required>
      <input type="hidden" name="rd" value="${safeRd}">
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Rate limiting (per-process, in-memory)
//
// Token/MAC comparisons are constant-time (see constantTimeEquals), which
// only protects against timing side-channels - it does nothing to stop an
// attacker from simply submitting many guesses at AUTH_TOKEN. This tracks
// failed attempts per client and locks a client out for a while once it
// crosses a threshold.
//
// This state is intentionally NOT shared across replicas or process
// restarts (consistent with the rest of this service's stateless design -
// see AGENTS.md). It raises the cost of online brute-forcing; it is not a
// substitute for a long, random AUTH_TOKEN.
// ---------------------------------------------------------------------------

const attemptsByClient = new Map();

// Best-effort client identifier. req.socket.remoteAddress is Traefik's
// container IP (authguard is only ever reached through the forwardAuth
// middleware), so use the real client IP from X-Forwarded-For instead.
//
// Take the LAST entry, not the first. Traefik's forwardAuth middleware
// always appends the IP that actually connected to it as the last hop of
// X-Forwarded-For, unconditionally - regardless of trustForwardHeader (see
// "Known Gotchas" below). Any earlier entries in the list are exactly the
// part a client controls, so taking the first entry let an attacker
// trivially bypass the rate limiter below by sending a different fake
// X-Forwarded-For prefix on every attempt.
function clientKey(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const hops = String(xff).split(',');
    return hops[hops.length - 1].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// Bound the map's size so a flood of distinct source IPs can't grow it
// without limit; opportunistically drop entries that have expired.
function pruneExpiredAttempts(now) {
  for (const [key, entry] of attemptsByClient) {
    if (entry.lockedUntil ? entry.lockedUntil <= now : entry.windowStart + RATE_LIMIT_WINDOW_MS <= now) {
      attemptsByClient.delete(key);
    }
  }
}

function isRateLimited(key) {
  const entry = attemptsByClient.get(key);
  return Boolean(entry && entry.lockedUntil && entry.lockedUntil > Date.now());
}

function recordFailedAttempt(key) {
  const now = Date.now();
  if (attemptsByClient.size > 10000) pruneExpiredAttempts(now);

  const entry = attemptsByClient.get(key);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    attemptsByClient.set(key, { windowStart: now, count: 1, lockedUntil: 0 });
    return;
  }
  entry.count += 1;
  if (entry.count >= RATE_LIMIT_MAX_ATTEMPTS) {
    entry.lockedUntil = now + RATE_LIMIT_LOCKOUT_MS;
  }
}

function clearFailedAttempts(key) {
  attemptsByClient.delete(key);
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

// Every response below is either an auth decision (200/302/401/429) or the
// login form itself - none of it should be cached by the browser or any
// intermediary (e.g. a CDN caching a /verify?token=... hit for one client
// and serving it to another).
function noStore(headers) {
  return { 'Cache-Control': 'no-store', ...headers };
}

function handleVerify(req, res) {
  const cookies = parseCookies(req.headers['cookie']);
  if (isValidSessionCookie(cookies[COOKIE_NAME])) {
    res.writeHead(200, noStore());
    res.end();
    return;
  }

  // X-Forwarded-Uri carries the original request's path + query string.
  const forwardedUri = req.headers['x-forwarded-uri'] || '/';
  const forwardedProto = firstHeaderValue(req.headers['x-forwarded-proto']) || 'http';
  let token = null;
  try {
    const parsed = new URL(forwardedUri, 'http://placeholder');
    token = parsed.searchParams.get('token');
  } catch (_err) {
    token = null;
  }

  if (token) {
    const key = clientKey(req);
    if (isRateLimited(key)) {
      res.writeHead(429, noStore({ 'Retry-After': String(Math.ceil(RATE_LIMIT_LOCKOUT_MS / 1000)) }));
      res.end('Too Many Requests');
      return;
    }
    if (isValidToken(token)) {
      clearFailedAttempts(key);
      const cookieValue = makeSessionCookieValue();
      const cookieHeader = sessionCookieHeader(cookieValue, forwardedProto);

      // GET/HEAD are safe to redirect: bounce the browser back to the same
      // URL with `token` stripped out, so it never lingers in the address
      // bar, history, or a Referer header beyond this one hop. For any
      // other method (a token-in-URL request isn't required to be a GET),
      // fall back to the old immediate-200 behavior instead - turning a
      // POST/PUT/DELETE into a GET via 302 would be worse than leaving the
      // token in the URL for that one request.
      const method = firstHeaderValue(req.headers['x-forwarded-method']) || 'GET';
      if (method === 'GET' || method === 'HEAD') {
        res.writeHead(302, noStore({
          'Set-Cookie': cookieHeader,
          Location: cleanRedirectTarget(forwardedUri),
        }));
        res.end();
        return;
      }

      res.writeHead(200, noStore({ 'Set-Cookie': cookieHeader }));
      res.end();
      return;
    }
    recordFailedAttempt(key);
  }

  const rd = encodeURIComponent(forwardedUri);
  res.writeHead(302, noStore({ Location: `${LOGIN_PATH}?rd=${rd}` }));
  res.end();
}

function handleLoginGet(req, res, query) {
  const html = renderLoginPage({ rd: query.rd, error: query.error === '1' });
  res.writeHead(200, noStore({ 'Content-Type': 'text/html; charset=utf-8' }));
  res.end(html);
}

async function handleLoginPost(req, res) {
  let body;
  try {
    body = await readBody(req);
  } catch (_err) {
    res.writeHead(400);
    res.end('Bad Request');
    return;
  }

  const form = querystring.parse(body);
  const rd = sanitizeRedirectTarget(firstValue(form.rd));
  const key = clientKey(req);

  if (isRateLimited(key)) {
    const html = renderLoginPage({ rd, rateLimited: true });
    res.writeHead(429, noStore({
      'Content-Type': 'text/html; charset=utf-8',
      'Retry-After': String(Math.ceil(RATE_LIMIT_LOCKOUT_MS / 1000)),
    }));
    res.end(html);
    return;
  }

  if (!isValidToken(firstValue(form.token))) {
    recordFailedAttempt(key);
    const html = renderLoginPage({ rd, error: true });
    res.writeHead(401, noStore({ 'Content-Type': 'text/html; charset=utf-8' }));
    res.end(html);
    return;
  }

  clearFailedAttempts(key);
  const forwardedProto = firstHeaderValue(req.headers['x-forwarded-proto']) || 'http';
  const cookieValue = makeSessionCookieValue();
  res.writeHead(302, noStore({
    'Set-Cookie': sessionCookieHeader(cookieValue, forwardedProto),
    Location: rd,
  }));
  res.end();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://placeholder');

  try {
    if (req.method === 'GET' && url.pathname === '/verify') {
      return handleVerify(req, res);
    }
    if (req.method === 'GET' && url.pathname === LOGIN_PATH) {
      return handleLoginGet(req, res, Object.fromEntries(url.searchParams));
    }
    if (req.method === 'POST' && url.pathname === LOGIN_PATH) {
      return await handleLoginPost(req, res);
    }
    res.writeHead(404);
    res.end('Not Found');
  } catch (err) {
    console.error('authguard: unhandled error', err);
    res.writeHead(500);
    res.end('Internal Server Error');
  }
});

// Only actually bind a port when run directly (`node server.js` / the
// container's CMD) - not when required by the test suite.
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`authguard listening on :${PORT}`);
  });
}

// Exposed for test/server.test.js. This stays a single file on purpose
// (see AGENTS.md) - exporting internals isn't a module split, it's just
// how the test suite reaches otherwise-private helpers.
module.exports = {
  server,
  constantTimeEquals,
  isValidToken,
  isValidSessionCookie,
  makeSessionCookieValue,
  sign,
  sessionCookieHeader,
  parseCookies,
  sanitizeRedirectTarget,
  cleanRedirectTarget,
  escapeHtml,
  firstValue,
  firstHeaderValue,
  noStore,
  clientKey,
  isRateLimited,
  recordFailedAttempt,
  clearFailedAttempts,
  attemptsByClient,
};
