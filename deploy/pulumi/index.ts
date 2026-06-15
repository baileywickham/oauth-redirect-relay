import * as path from "node:path";
import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";

// Deploys the oauth-redirect-relay broker as an AWS Lambda behind a public
// Function URL — the stable HTTPS endpoint you register as your OAuth redirect
// URI. Mirrors deploy/terraform; pick whichever IaC you already use.

const config = new pulumi.Config();
const signingKey = config.requireSecret("signingKey");
const functionName = config.get("functionName") ?? "oauth-redirect-relay-broker";
const allowLoopback = config.getBoolean("allowLoopback") ?? true;
const allowedOrigins = config.getObject<string[]>("allowedOrigins") ?? [];
const ttlSeconds = config.getNumber("ttlSeconds") ?? 600;
const logRetentionDays = config.getNumber("logRetentionDays") ?? 14;

// Reuse the prebuilt, dependency-free handler bundle shipped with the Terraform
// example, so there is exactly one handler source.
const bundlePath = path.join(
  __dirname,
  "..",
  "terraform",
  "lambda",
  "bundle",
  "index.mjs",
);

const role = new aws.iam.Role("broker-role", {
  name: `${functionName}-role`,
  assumeRolePolicy: JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Action: "sts:AssumeRole",
        Effect: "Allow",
        Principal: { Service: "lambda.amazonaws.com" },
      },
    ],
  }),
});

new aws.iam.RolePolicyAttachment("broker-logs", {
  role: role.name,
  policyArn:
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
});

// Declared explicitly so retention is managed (Lambda would otherwise create a
// never-expire log group on first invocation).
const logGroup = new aws.cloudwatch.LogGroup("broker-logs-group", {
  name: `/aws/lambda/${functionName}`,
  retentionInDays: logRetentionDays,
});

const broker = new aws.lambda.Function(
  "broker",
  {
    name: functionName,
    role: role.arn,
    runtime: "nodejs20.x",
    handler: "index.handler",
    code: new pulumi.asset.AssetArchive({
      "index.mjs": new pulumi.asset.FileAsset(bundlePath),
    }),
    timeout: 5,
    memorySize: 128,
    environment: {
      variables: {
        RELAY_SIGNING_KEY: signingKey,
        ALLOW_LOOPBACK: String(allowLoopback),
        ALLOWED_ORIGINS: allowedOrigins.join(","),
        TTL_SECONDS: String(ttlSeconds),
      },
    },
  },
  { dependsOn: [logGroup] },
);

// AuthType NONE by design: the OAuth provider must reach it unauthenticated.
// Security is the signed state + allowlist inside the function, not network ACLs.
const functionUrl = new aws.lambda.FunctionUrl("broker-url", {
  functionName: broker.name,
  authorizationType: "NONE",
});

/** Register this as your OAuth redirect URI and point dev boxes' redirect_uri at it. */
export const brokerUrl = functionUrl.functionUrl;
export const lambdaName = broker.name;
