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

```ts
import { createRelay } from "oauth-redirect-relay";

const relay = createRelay({ signingKey: process.env.RELAY_SIGNING_KEY! });

// 1. dev box: start the flow
const { state, nonce } = await relay.createState({
  target: "http://localhost:3000/callback",
  data: { provider: "slack" },
});
// store `nonce` (cookie), send user to the provider with
//   redirect_uri = <BROKER_URL>,  state = <state>

// 2. broker (the one registered HTTPS callback)
const result = await relay.handleCallback({ url: req.url });
// → { status: 302, location } | { status: 400, error, message }

// 3. dev box: finish the flow at your localhost callback
const { target, data } = await relay.verifyReturn({
  url: req.url,
  expectedNonce: storedNonce,
});
// then do your own token exchange with the `code`
```

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `signingKey` | — | HMAC-SHA256 secret (string) or `CryptoKey`, shared by dev box + broker |
| `ttlSeconds` | `600` | Signed lifetime of a state |
| `allowLoopback` | `true` | Allow `http://localhost` / `127.0.0.1` on any port (mode A) |
| `allowedOrigins` | `[]` | Extra exact origins allowed as targets |

Mode B (lock down, no loopback): `allowLoopback: false` + an explicit `allowedOrigins` list.

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
