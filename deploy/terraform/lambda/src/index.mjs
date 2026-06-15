// AWS Lambda handler for the oauth-redirect-relay broker, behind a Function URL
// (payload format 2.0). Reconstructs the incoming request URL, runs the library's
// handleCallback, and returns a 302 to the verified dev-box target or a 400.
//
// The Node 20 Lambda runtime provides global Web Crypto, so the pure library
// works here with no Bun and no extra runtime deps.

import { createRelay } from "oauth-redirect-relay";

const relay = createRelay({
  signingKey: process.env.RELAY_SIGNING_KEY,
  allowLoopback: process.env.ALLOW_LOOPBACK !== "false",
  allowedOrigins: (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  ttlSeconds: Number(process.env.TTL_SECONDS || "600"),
});

export const handler = async (event) => {
  const host = event.requestContext?.domainName ?? event.headers?.host;
  const path = event.rawPath ?? "/";
  const query = event.rawQueryString ? `?${event.rawQueryString}` : "";
  const url = `https://${host}${path}${query}`;

  const result = await relay.handleCallback({ url });

  if (result.status === 302) {
    return { statusCode: 302, headers: { location: result.location } };
  }

  return {
    statusCode: result.status,
    headers: { "content-type": "text/plain" },
    body: `OAuth relay error: ${result.error} — ${result.message}`,
  };
};
