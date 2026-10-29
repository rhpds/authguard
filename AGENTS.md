# authguard

A tiny, dependency-free ForwardAuth service for Traefik. Exchanges a shared
deploy-time token for a signed, expiring cookie so protected routes don't
need per-request credentials after the first successful login. See
`README.md` for the request flow diagram and Traefik wiring example.

## Stack

- Plain Node.js (`http`, `crypto`, `querystring`, `url` — core modules only,
  **no npm dependencies, no `package.json`**)
- Container image: UBI 10 Node 22 minimal (`registry.access.redhat.com/ubi10/nodejs-22-minimal`)

## Commands

```bash
# Run locally
AUTH_TOKEN=change-me SESSION_SECRET=change-me-too node server.js

# Build the container
podman build -t authguard .

# Run the container
podman run -p 8080:8080 -e AUTH_TOKEN=change-me -e SESSION_SECRET=change-me-too authguard

# Manual smoke test against a running instance
curl -i "http://localhost:8080/verify"                       # expect 302 -> /login
curl -i "http://localhost:8080/verify" -H "X-Forwarded-Uri: /?token=change-me"  # expect 302 + Set-Cookie + Location: / (token stripped)
curl -i "http://localhost:8080/login"                         # expect 200 html form
```

## Project Structure

```
server.js           Entire service: cookie signing/validation, route handlers, HTTP server
Containerfile       UBI10 node-minimal build, no package.json/npm install needed
README.md           Usage, config reference, Traefik integration, flow diagrams
test/server.test.js Unit tests (node --test) for the security-sensitive helpers
```

Everything lives in `server.js` on purpose — this service is intentionally
small enough to read top to bottom in one sitting. Resist the urge to split
it into modules unless it genuinely grows past that.

## Architecture

- **Stateless auth**: no database, no session store. A valid session is just
  a cookie value `<expiryMs>.<hmac-sha256(expiryMs, SESSION_SECRET)>`. Any
  instance with the same `SESSION_SECRET` can validate any cookie — safe to
  run multiple replicas without sticky sessions.
- **Rate limiting is the one exception to "stateless"**: failed token
  attempts are tracked per-client in an in-memory `Map` (`attemptsByClient`)
  to slow down brute-forcing `AUTH_TOKEN`. This is deliberately
  per-process — it resets on restart and isn't shared across replicas. Don't
  promote it to a shared/persistent store (see Boundaries below).
- **`/verify`** (called by Traefik's `forwardAuth` middleware on every
  request to a protected router):
  1. If the request has a valid session cookie → `200`.
  2. Else, look for `?token=` in `X-Forwarded-Uri` (the original request's
     path + query, set by Traefik) → if it matches `AUTH_TOKEN`, set the
     session cookie. For GET/HEAD, `302`-redirect back to the same URL with
     `token` stripped (`cleanRedirectTarget`) so it doesn't linger in the
     browser's history/Referer; for any other method, return `200` instead
     (a `302` would otherwise turn a POST/PUT/DELETE into a GET on
     redirect).
  3. Else → `302` to `/login?rd=<original uri>`.
- **`/login`** (GET renders the form, POST validates the submitted token).
  On success, sets the session cookie and `302`s to the sanitized `rd`
  target. `rd` is restricted to same-origin relative paths
  (`sanitizeRedirectTarget`) to avoid an open-redirect.
- Both token and cookie-MAC comparisons go through `constantTimeEquals`,
  which always runs `crypto.timingSafeEqual` against equal-length buffers
  (even on length mismatch) so comparison timing doesn't leak length.
- `Set-Cookie` gets the `Secure` flag automatically based on
  `X-Forwarded-Proto` — whether that requires `trustForwardHeader: true` on
  the Traefik middleware depends on the deployment target; see "Known
  Gotchas" below.

## Code Conventions

- Zero runtime dependencies. If a feature seems to need an npm package,
  prefer implementing the small piece needed with Node core modules instead
  — that's the whole point of this service.
- Keep handlers synchronous/small; the only `async` path is the POST
  `/login` body read (`readBody`).
- Env vars are read once at module load (top of `server.js`), not re-read
  per-request.
- Any new redirect target must go through `sanitizeRedirectTarget` — never
  write `res.writeHead(302, { Location: <user input> })` directly.
- Any new secret comparison must go through `constantTimeEquals` — never use
  `===` on tokens/MACs.

## Boundaries

**Always:**
- Keep this a single dependency-free file unless there's a strong reason to
  split it.
- Run `node --test` before committing. Add/update a test in
  `test/server.test.js` for any new helper or changed edge case.
- Run the manual smoke-test curls above after touching `/verify` or
  `/login` logic.
- Update `README.md`'s flow diagrams if the `/verify` decision logic changes.

**Never:**
- Add an npm dependency / `package.json` without discussing it first — this
  service's whole value proposition is "no supply chain to worry about."
- Log `AUTH_TOKEN`, `SESSION_SECRET`, or raw cookie values.
- Compare secrets with `===` or any non-constant-time method.
- Allow `rd`/redirect targets that aren't same-origin relative paths.

**Ask first:**
- Adding a persistent session store (defeats the stateless design).
- Changing the cookie name (`nookbag_auth`) — downstream Traefik configs
  reference it explicitly in `addAuthCookiesToResponse`.

## Known Gotchas

- `authguard` is deployment-target-agnostic, but the `trustForwardHeader`
  setting on the Traefik `forwardAuth` middleware in front of it is **not**
  — it must match how *that* Traefik terminates TLS:
  - **VM / podman-compose** (Traefik terminates real TLS itself, is the
    network edge): use `trustForwardHeader: false`. Traefik will correctly
    self-compute `X-Forwarded-Proto`/`X-Forwarded-Uri` from the real
    connection it holds; no client header needs to be (or should be)
    trusted.
  - **OpenShift single-pod chart** (Traefik only ever listens on plain HTTP
    inside the Pod; the OpenShift Router terminates TLS one hop upstream and
    overwrites `X-Forwarded-Proto`/`Host`/`Port` by default before
    forwarding): use `trustForwardHeader: true`. Without it, Traefik would
    always see "http" locally (no TLS listener of its own) and the session
    cookie would never get the `Secure` flag.

  Using the wrong value per environment either breaks the `Secure` cookie
  flag (OCP without `true`) or lets a client spoof it (VM with `true`
  instead of `false`). See `rhpds/showroom` (`vm_workload_showroom`) and
  `rhpds/showroom-deployer` (`showroom-single-pod` chart) for the reference
  wiring of each.
- Traefik needs `addAuthCookiesToResponse: [nookbag_auth]` on the
  `forwardAuth` middleware, or the `Set-Cookie` header from `/verify` is
  swallowed and never reaches the browser.
- The `/login` router must be registered on a higher priority and **without**
  the auth middleware attached, or the login page itself becomes
  unreachable (infinite redirect loop).
- `test/server.test.js` covers the pure helpers (cookie signing/validation,
  `sanitizeRedirectTarget`, `cleanRedirectTarget`, `escapeHtml`, rate
  limiting) but not the HTTP handlers themselves — still verify `/verify`
  and `/login` manually with the curl commands above (and ideally against a
  real Traefik instance) before committing.
- The GET/HEAD-vs-other-methods branch in `handleVerify` (token-in-URL
  redirect) reads the original request's method from `X-Forwarded-Method`,
  defaulting to `GET` if absent. Like `X-Forwarded-Uri`/`X-Forwarded-Proto`,
  this header is only trustworthy with `trustForwardHeader: true` - but
  unlike those two, a spoofed value here only changes *how* the same cookie
  gets issued (302-redirect vs. immediate 200), not *whether* it does, so
  spoofing it isn't a meaningful security issue on its own.
- `clientKey()` (used for rate limiting) reads the **last** hop of
  `X-Forwarded-For`, not the first. Traefik always appends the IP that
  actually connected to it as the last hop, unconditionally - regardless of
  `trustForwardHeader` - so that hop stays trustworthy even though the
  earlier ones don't. Taking the first hop instead would let a client
  rotate a fake prefix per request and bypass the rate limiter entirely;
  don't "simplify" this back to `split(',')[0]`.

## Git Workflow

- This package is intended to be split out into its own repository. Once
  that happens, branch from `main`, prefix with `feature/`, `fix/`, or
  `chore/`, and open PRs against `main`.
