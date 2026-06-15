# Deploy the broker to AWS (Terraform)

Provisions the `oauth-redirect-relay` broker as an AWS Lambda function behind a
public **Lambda Function URL** — a stable HTTPS endpoint with no API Gateway.
That URL is the single redirect URI you register with your OAuth provider.

```
Lambda Function URL (HTTPS)  →  Lambda (nodejs20.x, this module)
                                   verifies signed state + allowlist
                                   302 → http://localhost:<port>/callback
```

## Prerequisites

- Terraform >= 1.3 and AWS credentials configured (`aws configure` or env vars).

That's it — the handler ships as a prebuilt, dependency-free bundle
(`lambda/bundle/index.mjs`), so there is **no npm install** and nothing to build.

## Deploy

```bash
cd deploy/terraform

# Pass the signing key as a variable (never commit it).
export TF_VAR_signing_key="$(openssl rand -hex 32)"   # or your existing shared key
terraform init
terraform apply

terraform output broker_url
# → https://<id>.lambda-url.<region>.on.aws/
```

Register `broker_url` as your OAuth app's redirect URI, and set each dev box's
`redirect_uri` to it. The **same `signing_key`** must be given to the dev boxes'
`createRelay({ signingKey })`.

## Updating the bundled handler (maintainers)

The committed `lambda/bundle/index.mjs` pins a published `oauth-redirect-relay`
version. To pick up a new library release, rebuild it:

```bash
cd deploy/terraform/lambda
# bump "oauth-redirect-relay" in package.json if needed
npm install
npm run bundle          # esbuild → bundle/index.mjs
git add bundle/index.mjs package.json package-lock.json
```

## Inputs

| Variable | Default | Description |
|----------|---------|-------------|
| `signing_key` | — (required, sensitive) | HMAC-SHA256 secret shared with the dev boxes |
| `function_name` | `oauth-redirect-relay-broker` | Lambda + IAM role name |
| `allow_loopback` | `true` | Allow `localhost`/`127.0.0.1` targets (mode A); `false` = mode B |
| `allowed_origins` | `[]` | Extra exact origins allowed as targets |
| `ttl_seconds` | `600` | Signed state lifetime |
| `log_retention_days` | `14` | CloudWatch log retention |
| `tags` | `{}` | Tags on all resources |

## Outputs

| Output | Description |
|--------|-------------|
| `broker_url` | The HTTPS endpoint to register as your redirect URI |
| `function_name` | Deployed Lambda name |
| `log_group` | CloudWatch log group |

## Use as a module

```hcl
module "oauth_broker" {
  source = "github.com/baileywickham/oauth-redirect-relay//deploy/terraform?ref=v0.1.0"

  signing_key     = var.oauth_relay_signing_key
  allow_loopback  = false
  allowed_origins = ["https://alice.dev.example.com"]
}

output "broker_url" {
  value = module.oauth_broker.broker_url
}
```

Because the handler is a committed, dependency-free bundle, remote-module use needs
nothing extra — `terraform init` fetches the module and `apply` zips the bundle as-is.

## Notes

- **Function URL auth is `NONE`** by design: the OAuth provider must reach it
  unauthenticated. Security is the signed state + origin allowlist inside the
  function, not network ACLs.
- `signing_key` lands in the Lambda's environment variables. For stricter setups,
  swap it for AWS Secrets Manager / SSM Parameter Store and read it at cold start.
- Tear down with `terraform destroy`.
