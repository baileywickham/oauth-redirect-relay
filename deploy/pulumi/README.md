# Deploy the broker to AWS (Pulumi)

Provisions the `oauth-redirect-relay` broker as an AWS Lambda behind a public
**Function URL** — the stable HTTPS endpoint you register as your OAuth redirect
URI. Same shape as [`../terraform`](../terraform); use whichever IaC you prefer.

It reuses the prebuilt, dependency-free handler bundle from the Terraform example
(`../terraform/lambda/bundle/index.mjs`), so there's nothing to build.

## Prerequisites

- Pulumi CLI and AWS credentials (`aws configure` or env vars).
- Node + a package manager (to install `@pulumi/aws`).

## Deploy

```bash
cd deploy/pulumi
npm install

pulumi stack init dev
pulumi config set aws:region us-west-2
pulumi config set --secret signingKey "$(openssl rand -hex 32)"   # or your existing shared key

pulumi up

pulumi stack output brokerUrl
# → https://<id>.lambda-url.<region>.on.aws/
```

Register `brokerUrl` as your OAuth app's redirect URI, and set each dev box's
`redirect_uri` (or `OAUTH_RELAY_BROKER_URL`) to it. The **same `signingKey`** must
be given to the dev boxes' `createRelay({ signingKey })`.

## Config

| Key | Default | Meaning |
|-----|---------|---------|
| `signingKey` (secret) | — (required) | HMAC-SHA256 secret shared with the dev boxes |
| `functionName` | `oauth-redirect-relay-broker` | Lambda + IAM role name |
| `allowLoopback` | `true` | Allow `localhost`/`127.0.0.1` targets (mode A); `false` = mode B |
| `allowedOrigins` | `[]` | Extra exact origins allowed as targets (`pulumi config set --path allowedOrigins[0] https://alice.dev.example.com`) |
| `ttlSeconds` | `600` | Signed state lifetime |
| `logRetentionDays` | `14` | CloudWatch log retention |

## Outputs

| Output | Description |
|--------|-------------|
| `brokerUrl` | The HTTPS endpoint to register as your redirect URI |
| `lambdaName` | Deployed Lambda name |

## Consuming the broker from another project

The broker is a **single shared resource** — deploy it once; every dev box just needs its
URL. So consume it by reference, not by code:

- Simplest: set `OAUTH_RELAY_BROKER_URL` to `brokerUrl` in each dev's environment.
- From another Pulumi stack: `new pulumi.StackReference("<org>/oauth-redirect-relay-broker/dev").getOutput("brokerUrl")`.

(If you instead want a stack to *own* the broker's lifecycle as a reusable module, wrap this
program's resources in a `pulumi.ComponentResource` and publish it as an npm package — the
idiomatic Pulumi way to share modules. Overkill for a single shared broker.)

## Notes

- **Function URL auth is `NONE`** by design: the OAuth provider must reach it
  unauthenticated. Security is the signed state + origin allowlist inside the
  function, not network ACLs.
- `signingKey` lands in the Lambda's environment. For stricter setups, read it
  from AWS Secrets Manager / SSM at cold start instead.
- Tear down with `pulumi destroy`.
