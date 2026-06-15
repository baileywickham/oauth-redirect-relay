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
- Node + npm (only to install the function's one dependency before packaging).

## Deploy

```bash
cd deploy/terraform

# 1. Install the function's dependency so it gets zipped into the Lambda.
npm install --prefix lambda

# 2. Provision. Pass the signing key as a variable (never commit it).
export TF_VAR_signing_key="$(openssl rand -hex 32)"   # or your existing shared key
terraform init
terraform apply

# 3. Grab the endpoint.
terraform output broker_url
# → https://<id>.lambda-url.<region>.on.aws/
```

Register `broker_url` as your OAuth app's redirect URI, and set each dev box's
`redirect_uri` to it. The **same `signing_key`** must be given to the dev boxes'
`createRelay({ signingKey })`.

> Re-run `npm install --prefix lambda` and `terraform apply` after bumping the
> `oauth-redirect-relay` version in `lambda/package.json`.

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

Note: when consumed as a remote module, run `npm install --prefix lambda` inside the
downloaded module directory (under `.terraform/modules/...`) before `apply`, or vendor
the dependency. For hands-off CI, the [trusted-publishing GitHub Actions](../../.github/workflows/publish.yml)
pattern or a prebuilt bundle is a cleaner fit — see the repo README.

## Notes

- **Function URL auth is `NONE`** by design: the OAuth provider must reach it
  unauthenticated. Security is the signed state + origin allowlist inside the
  function, not network ACLs.
- `signing_key` lands in the Lambda's environment variables. For stricter setups,
  swap it for AWS Secrets Manager / SSM Parameter Store and read it at cold start.
- Tear down with `terraform destroy`.
