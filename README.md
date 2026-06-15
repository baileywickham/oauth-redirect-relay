# oauth-redirect-relay

Share **one** registered OAuth redirect URI across many dev boxes — safely.

OAuth providers match redirect URIs by exact string, and some (Slack) reject
`http://localhost` and forbid wildcards. Instead of registering every dev machine,
register one HTTPS broker URL, sign the real dev-box target into the OAuth `state`, and let
a tiny broker verify it and bounce the `code` back to the right machine.

This library gives you the signed-state codec, the broker verification (with an origin
allowlist that prevents open redirects), and a CSRF nonce. It does **not** do PKCE or the
token exchange — that stays in your app's OAuth client.

## Install

```bash
bun add oauth-redirect-relay
```

## Flow

The easiest path: hand it the authorize URL your OAuth client already builds, and the
relay rewrites the `redirect_uri` to the broker and signs the `state` for you.

```ts
import { createRelay } from "oauth-redirect-relay";

const relay = createRelay({
  signingKey: process.env.RELAY_SIGNING_KEY!,
  brokerUrl: "https://broker.example.com/oauth-relay/callback",
});

// 1. dev box: wrap the provider authorize URL, then redirect the user to it
const { url, nonce } = await relay.wrapAuthorizeUrl(googleAuthUrl);
// (optionally) stash `nonce` in a short-lived cookie, then redirect to `url`

// 2. broker (the one registered HTTPS callback)
const result = await relay.handleCallback({ url: req.url });
// → { status: 302, location } | { status: 400, error, message }

// 3. dev box: finish the flow at your localhost callback
const { target, providerState, data } = await relay.verifyReturn({
  url: req.url,
  expectedNonce: storedNonce, // omit to enforce signature + expiry only
});
// `providerState` is the OAuth `state` your client originally set — verify it as usual,
// then do your own token exchange (use the broker URL as redirect_uri).
```

`wrapAuthorizeUrl` preserves the provider's original `state` (returned as `providerState`)
and any other query params. For full control, the lower-level `createState({ target, data,
providerState })` builds a signed state directly.

### Server-initiated flows (no per-browser nonce)

When the same server starts *and* finishes the flow and has nowhere to stash a per-browser
nonce, call `verifyReturn({ url })` **without** `expectedNonce`: the signature and expiry are
still fully enforced; only the browser-binding check is skipped.

`verifyReturn` also accepts the state directly — `verifyReturn({ state })` — for callbacks
that have already parsed it off the request.

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `signingKey` | — | HMAC-SHA256 secret (string) or `CryptoKey`, shared by dev box + broker |
| `brokerUrl` | — | Broker callback URL; required for `wrapAuthorizeUrl` |
| `ttlSeconds` | `600` | Signed lifetime of a state |
| `allowLoopback` | `true` | Allow `http://localhost` / `127.0.0.1` on any port (mode A) |
| `allowedOrigins` | `[]` | Extra exact origins allowed as targets |

Mode B (lock down, no loopback): `allowLoopback: false` + an explicit `allowedOrigins` list.

`isRelayState(value)` tells a relay token apart from a legacy state, e.g. to roll out the
relay incrementally on a callback that may still receive un-wrapped states.

## Hosting the broker

`handleCallback` is framework-agnostic — it takes a URL and returns `{ status, location }`,
so it drops into any server. See [`examples/express-broker.ts`](examples/express-broker.ts)
for a ~30-line Express handler you can copy:

```ts
app.get("/oauth-relay/callback", expressBroker(relay)); // from the example
```

## Example broker

```bash
RELAY_SIGNING_KEY=your-secret bun examples/broker.ts
```

## Deploy a broker

The broker is stateless — one route, one secret. Deploy it to AWS as a Lambda behind a
public Function URL (the stable HTTPS endpoint you register as your redirect URI):

```bash
cd deploy/terraform
export TF_VAR_signing_key="$(openssl rand -hex 32)"
terraform init && terraform apply
terraform output broker_url
```

See [`deploy/terraform/README.md`](deploy/terraform/README.md) for inputs, outputs, and
using it as a remote module.

## Security notes

- The allowlist is what stops this from being an open redirect — keep `allowLoopback: false`
  in any non-dev deployment and list exact origins.
- The signing key is shared by both sides; use a dev-only key, never your prod app secret.
- This library covers signed state + allowlist + nonce. Use PKCE in your OAuth client too.
