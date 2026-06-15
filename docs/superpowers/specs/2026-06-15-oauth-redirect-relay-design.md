# oauth-redirect-relay — Design

**Date:** 2026-06-15
**Status:** Approved, ready for implementation plan

## Problem

OAuth providers match redirect URIs by exact string and many (notably Slack) reject
`http://localhost` and forbid wildcards. Supporting many developer machines therefore
means either registering each box's URL by hand or running tunnels. The signed-state
broker pattern avoids both: register **one** stable HTTPS callback with the provider,
encode the real dev-box target in a signed `state`, and have a small broker verify the
signature and 302 the OAuth `code` back to the correct local machine.

Done naively this is an open redirect. This library exists to make the safe version the
easy version.

## Scope

In scope (single, focused package):

- Signed-state codec (create / verify) using HMAC-SHA256.
- A framework-agnostic broker handler that verifies state, enforces an allowlist, and
  returns a redirect instruction (does **not** own an HTTP server).
- CSRF nonce, expiry (`exp`), and arbitrary signed passthrough data.
- An example runnable Bun broker server.

Out of scope:

- PKCE helpers — orthogonal to redirect routing; left to the app's OAuth client.
- The app's token exchange (`code` → token).
- Any provider-specific OAuth client logic.

## Runtime / crypto

Core uses **Web Crypto (`crypto.subtle`, HMAC-SHA256)** so it runs on Bun, Node 18+,
Deno, and edge runtimes (Cloudflare Workers / Vercel Edge), since a broker is often
deployed to the edge. Consequence: the public API is **async**.

## API surface

One factory, because the dev box and the broker share the same signing key.

```ts
const relay = createRelay({
  signingKey,                 // string | CryptoKey — HMAC-SHA256 secret, shared by both sides
  ttlSeconds = 600,           // signed exp; stale state rejected
  allowLoopback = true,       // mode A: localhost / 127.0.0.1 (any port) pass by default
  allowedOrigins = [],        // explicit extra origins; allowLoopback:false + this list = mode B
})
```

Three methods across the two sides:

```ts
// ── dev box: start the flow ──
const { state, nonce } = await relay.createState({
  target: "http://localhost:3000/callback",  // where to bounce back to
  data?: { provider: "slack" },              // signed passthrough
})
// dev box stores `nonce` (cookie/local store), then sends the user to the provider with
//   redirect_uri = <BROKER_URL>,  state = <state>

// ── broker: the one registered HTTPS callback ──
const result = await relay.handleCallback({ url: req.url })
//   verifies sig + exp, checks target origin ∈ allowlist, re-attaches code/state
//   → { status: 302, location } | { status: 400, error }

// ── dev box: finish the flow ──
const { target, data } = await relay.verifyReturn({
  url: req.url,                // the localhost callback that was hit
  expectedNonce: storedNonce,  // CSRF check
})  // throws typed error on bad sig / expired / nonce mismatch / malformed
```

### Signed state format

Compact, base64url-encoded: payload `{ t: target, n: nonce, x: exp, d?: data }` plus an
HMAC-SHA256 signature over the payload. The broker needs the key only to verify. The
nonce is validated by the dev box (against its stored copy), not by the broker.

## Data flow (Slack example)

```
dev box          createState() → state (+nonce); store nonce in cookie
  │  GET slack.com/oauth/authorize?redirect_uri=BROKER&state=STATE
  ▼
Slack ──code+state──▶ BROKER /callback   (the one registered HTTPS URL)
  │                      handleCallback(): verify sig + exp → check target origin
  │                      302 → http://localhost:3000/callback?code=…&state=STATE
  ▼
dev box localhost  verifyReturn(): verify sig + exp + nonce == cookie → { target, data }
                   → app performs its own token exchange (code → token)
```

## Error handling

Every rejection is explicit; the broker never 302s on a failure.

- `handleCallback` returns `{ status: 400, error }` with a typed error code on: missing or
  garbled state, bad signature, expired, **target origin not allowed** (the open-redirect
  guard), or missing `code`.
- `verifyReturn` throws typed errors: `InvalidSignature`, `Expired`, `NonceMismatch`,
  `MalformedState`. Callers catch and render an auth-failed page.
- Errors are a discriminated union / named classes so callers branch on a code, not a
  string.
- HMAC verification uses Web Crypto's constant-time `verify` to avoid timing leaks.

## Allowlist (the safety mechanism)

- Default (mode A): `allowLoopback: true` — `http://localhost:<port>` and
  `http://127.0.0.1:<port>` pass on any port; `allowedOrigins` adds explicit extras.
- Mode B: `allowLoopback: false` with an explicit `allowedOrigins` list — only those exact
  origins pass; loopback is rejected.
- Origin comparison is on scheme + host + port, parsed via `URL`, not substring matching.

## Testing (`bun test`)

- Round-trip happy path: `createState` → `handleCallback` → `verifyReturn`.
- Tampering: flip a byte in state → `InvalidSignature`; swapping `target` is caught by sig.
- Expiry: `ttlSeconds: 0` / clock past `exp` → `Expired`. Clock is an injectable parameter
  so assertions are deterministic and do not depend on real wall-clock time.
- Allowlist: loopback passes; non-loopback rejected unless in `allowedOrigins`;
  `allowLoopback: false` rejects localhost (mode B).
- Nonce: mismatch → `NonceMismatch`.
- Example Bun broker smoke test: `/callback` with a forged vs a valid state.

## Module layout

```
src/relay.ts        createRelay + the three methods
src/state.ts        encode/decode + HMAC sign/verify (Web Crypto)
src/allowlist.ts    origin check (loopback + explicit)
src/errors.ts       typed errors
src/index.ts        public exports
examples/broker.ts  runnable Bun server
*.test.ts           colocated tests
```

## Non-goals / explicit deferrals

- No PKCE, no token exchange, no provider SDKs.
- No persistent storage — state is self-contained and signed; nonce storage is the app's job.
- No built-in HTTP server in the core; only the example uses Bun's server.
