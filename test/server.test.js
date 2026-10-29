'use strict';

// Unit tests for the security-sensitive helpers in server.js. Uses Node's
// built-in test runner (`node --test`) - no npm dependencies, per
// AGENTS.md's "zero runtime dependencies" rule.
//
// Run with:  node --test
//
// server.js reads AUTH_TOKEN/SESSION_SECRET at module load time and exits
// if they're missing, so we set them *before* requiring it below.

process.env.AUTH_TOKEN = 'test-auth-token';
process.env.SESSION_SECRET = 'test-session-secret'; // pragma: allowlist secret
process.env.SESSION_TTL_SECONDS = '60';
process.env.RATE_LIMIT_MAX_ATTEMPTS = '3';
process.env.RATE_LIMIT_WINDOW_SECONDS = '60';
process.env.RATE_LIMIT_LOCKOUT_SECONDS = '300';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
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
} = require('../server.js');

test('constantTimeEquals', async (t) => {
  await t.test('matches equal strings', () => {
    assert.equal(constantTimeEquals('abc', 'abc'), true);
  });

  await t.test('rejects different strings of the same length', () => {
    assert.equal(constantTimeEquals('abc', 'abd'), false);
  });

  await t.test('rejects different-length strings without throwing', () => {
    assert.equal(constantTimeEquals('abc', 'ab'), false);
    assert.equal(constantTimeEquals('ab', 'abc'), false);
  });

  await t.test('rejects empty vs non-empty', () => {
    assert.equal(constantTimeEquals('', 'a'), false);
  });
});

test('isValidToken', async (t) => {
  await t.test('accepts the configured AUTH_TOKEN', () => {
    assert.equal(isValidToken('test-auth-token'), true);
  });

  await t.test('rejects a wrong token', () => {
    assert.equal(isValidToken('nope'), false);
  });

  await t.test('rejects null/undefined/empty without throwing', () => {
    assert.equal(isValidToken(null), false);
    assert.equal(isValidToken(undefined), false);
    assert.equal(isValidToken(''), false);
  });
});

test('isValidSessionCookie', async (t) => {
  await t.test('accepts a freshly minted cookie', () => {
    const cookie = makeSessionCookieValue();
    assert.equal(isValidSessionCookie(cookie), true);
  });

  await t.test('rejects an expired cookie', () => {
    const expiryMs = Date.now() - 1000;
    const cookie = `${expiryMs}.${sign(expiryMs)}`;
    assert.equal(isValidSessionCookie(cookie), false);
  });

  await t.test('rejects a tampered MAC', () => {
    const expiryMs = Date.now() + 60_000;
    const cookie = `${expiryMs}.not-the-real-mac`;
    assert.equal(isValidSessionCookie(cookie), false);
  });

  await t.test('rejects a forged expiry with a mismatched MAC', () => {
    const realCookie = makeSessionCookieValue();
    const [, mac] = realCookie.split('.');
    const forged = `${Date.now() + 999_999_999}.${mac}`;
    assert.equal(isValidSessionCookie(forged), false);
  });

  await t.test('rejects malformed values (no dot, empty, undefined)', () => {
    assert.equal(isValidSessionCookie('no-dot-here'), false);
    assert.equal(isValidSessionCookie(''), false);
    assert.equal(isValidSessionCookie(undefined), false);
  });

  await t.test('rejects a non-numeric expiry', () => {
    assert.equal(isValidSessionCookie('not-a-number.somemac'), false);
  });
});

test('sessionCookieHeader', async (t) => {
  await t.test('omits Secure over http', () => {
    const header = sessionCookieHeader('abc', 'http');
    assert.match(header, /^nookbag_auth=abc;/);
    assert.ok(!header.includes('Secure'));
    assert.ok(header.includes('HttpOnly'));
    assert.ok(header.includes('SameSite=Lax'));
  });

  await t.test('adds Secure over https', () => {
    const header = sessionCookieHeader('abc', 'https');
    assert.ok(header.includes('Secure'));
  });
});

test('parseCookies', async (t) => {
  await t.test('parses a simple cookie header', () => {
    assert.deepEqual(parseCookies('a=1; b=2'), { a: '1', b: '2' });
  });

  await t.test('returns {} for missing/empty header', () => {
    assert.deepEqual(parseCookies(undefined), {});
    assert.deepEqual(parseCookies(''), {});
  });

  await t.test('decodes percent-encoded values', () => {
    assert.deepEqual(parseCookies('a=hello%20world'), { a: 'hello world' });
  });
});

test('sanitizeRedirectTarget', async (t) => {
  await t.test('allows a normal relative path', () => {
    assert.equal(sanitizeRedirectTarget('/dashboard'), '/dashboard');
  });

  await t.test('defaults to / for empty/missing input', () => {
    assert.equal(sanitizeRedirectTarget(''), '/');
    assert.equal(sanitizeRedirectTarget(undefined), '/');
    assert.equal(sanitizeRedirectTarget(null), '/');
  });

  await t.test('defaults to / for non-string input (e.g. an array)', () => {
    assert.equal(sanitizeRedirectTarget(['/a', '/b']), '/');
  });

  await t.test('rejects a path with no leading slash', () => {
    assert.equal(sanitizeRedirectTarget('evil.com'), '/');
  });

  await t.test('rejects protocol-relative //host', () => {
    assert.equal(sanitizeRedirectTarget('//evil.com'), '/');
  });

  await t.test('rejects an absolute URL with a scheme', () => {
    assert.equal(sanitizeRedirectTarget('https://evil.com'), '/');
    assert.equal(sanitizeRedirectTarget('/redirect?u=http://evil.com'), '/');
  });

  await t.test('rejects the backslash open-redirect bypass', () => {
    // Browsers normalize a leading "\" the same as "/", so these would
    // otherwise resolve to the scheme-relative "//evil.com".
    assert.equal(sanitizeRedirectTarget('/\\evil.com'), '/');
    assert.equal(sanitizeRedirectTarget('/\\/evil.com'), '/');
    assert.equal(sanitizeRedirectTarget('/foo\\evil.com'), '/');
  });
});

test('cleanRedirectTarget', async (t) => {
  await t.test('strips the token param but keeps the path', () => {
    assert.equal(cleanRedirectTarget('/nookbag?token=secret'), '/nookbag');
  });

  await t.test('keeps other query params, dropping only token', () => {
    assert.equal(cleanRedirectTarget('/nookbag?token=secret&foo=bar'), '/nookbag?foo=bar');
  });

  await t.test('leaves a bare path with no trailing "?" when token was the only param', () => {
    assert.equal(cleanRedirectTarget('/?token=secret'), '/');
  });

  await t.test('defaults to / for malformed input', () => {
    assert.equal(cleanRedirectTarget(''), '/');
    assert.equal(cleanRedirectTarget(undefined), '/');
  });

  await t.test('still goes through sanitizeRedirectTarget (no open redirect via a spoofed host)', () => {
    assert.equal(cleanRedirectTarget('//evil.com/?token=secret'), '/');
  });
});

test('escapeHtml', async (t) => {
  await t.test('escapes all HTML-significant characters', () => {
    assert.equal(
      escapeHtml(`<script>alert('x')&"y"</script>`),
      '&lt;script&gt;alert(&#39;x&#39;)&amp;&quot;y&quot;&lt;/script&gt;',
    );
  });

  await t.test('coerces non-string input', () => {
    assert.equal(escapeHtml(123), '123');
  });
});

test('firstValue', async (t) => {
  await t.test('passes through a plain string', () => {
    assert.equal(firstValue('a'), 'a');
  });

  await t.test('takes the first element of an array (duplicated form field)', () => {
    assert.equal(firstValue(['a', 'b']), 'a');
  });

  await t.test('passes through undefined', () => {
    assert.equal(firstValue(undefined), undefined);
  });
});

test('firstHeaderValue', async (t) => {
  await t.test('passes through a single value', () => {
    assert.equal(firstHeaderValue('https'), 'https');
  });

  await t.test('takes the first value of a comma-joined duplicated header', () => {
    assert.equal(firstHeaderValue('https, http'), 'https');
  });

  await t.test('passes through falsy values unchanged', () => {
    assert.equal(firstHeaderValue(undefined), undefined);
    assert.equal(firstHeaderValue(''), '');
  });
});

test('noStore', async (t) => {
  await t.test('adds Cache-Control: no-store without extra headers', () => {
    assert.deepEqual(noStore(), { 'Cache-Control': 'no-store' });
  });

  await t.test('merges in extra headers', () => {
    assert.deepEqual(noStore({ Location: '/x' }), { 'Cache-Control': 'no-store', Location: '/x' });
  });
});

test('rate limiting', async (t) => {
  const fakeReq = (ip) => ({ headers: { 'x-forwarded-for': ip }, socket: { remoteAddress: '10.0.0.1' } });

  t.afterEach(() => attemptsByClient.clear());

  await t.test('clientKey prefers X-Forwarded-For over the socket address', () => {
    assert.equal(clientKey(fakeReq('1.2.3.4')), '1.2.3.4');
    assert.equal(clientKey({ headers: {}, socket: { remoteAddress: '10.0.0.1' } }), '10.0.0.1');
  });

  await t.test('clientKey takes the LAST X-Forwarded-For hop, not the first', () => {
    // Traefik always appends the real connecting IP as the last hop,
    // regardless of trustForwardHeader; any earlier hop is attacker-
    // controlled. A client spoofing the first hop must not get a fresh
    // rate-limit bucket on every attempt.
    assert.equal(clientKey(fakeReq('attacker-spoofed-ip, 9.9.9.9')), '9.9.9.9');
    assert.equal(clientKey(fakeReq('1.1.1.1, 2.2.2.2, 9.9.9.9')), '9.9.9.9');
  });

  await t.test('is not rate limited before any failed attempts', () => {
    assert.equal(isRateLimited('1.2.3.4'), false);
  });

  await t.test('locks out after RATE_LIMIT_MAX_ATTEMPTS failures', () => {
    const key = '5.5.5.5';
    recordFailedAttempt(key);
    recordFailedAttempt(key);
    assert.equal(isRateLimited(key), false, 'not locked out before the limit');
    recordFailedAttempt(key); // 3rd failure == RATE_LIMIT_MAX_ATTEMPTS
    assert.equal(isRateLimited(key), true, 'locked out at the limit');
  });

  await t.test('does not affect a different client', () => {
    const key = '6.6.6.6';
    const other = '7.7.7.7';
    for (let i = 0; i < 3; i += 1) recordFailedAttempt(key);
    assert.equal(isRateLimited(key), true);
    assert.equal(isRateLimited(other), false);
  });

  await t.test('clearFailedAttempts resets the lockout', () => {
    const key = '8.8.8.8';
    for (let i = 0; i < 3; i += 1) recordFailedAttempt(key);
    assert.equal(isRateLimited(key), true);
    clearFailedAttempts(key);
    assert.equal(isRateLimited(key), false);
  });
});
