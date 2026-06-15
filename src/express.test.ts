import { test, expect } from "bun:test";
import { createRelay } from "./relay";
import { expressBroker } from "./express";

const SECRET = "express-secret";
const BROKER = "https://broker.example.com/oauth-relay/callback";

// Minimal Express-like req/res doubles.
function makeReq(originalUrl: string, headers: Record<string, string>) {
  return {
    protocol: "https",
    originalUrl,
    get: (name: string) => headers[name.toLowerCase()],
  };
}

function makeRes() {
  const out: { status: number; location?: string; body?: string } = { status: 200 };
  return {
    res: {
      redirect(location: string) {
        out.status = 302;
        out.location = location;
      },
      status(code: number) {
        out.status = code;
        return this;
      },
      send(body: string) {
        out.body = body;
      },
    },
    out,
  };
}

test("expressBroker 302s a valid relay callback to the dev-box target", async () => {
  const relay = createRelay({ signingKey: SECRET, brokerUrl: BROKER, now: () => 1_000 });
  const target = "http://localhost:3000/google-workspace/callback";
  const { state } = await relay.wrapAuthorizeUrl(
    `https://accounts.google.com/auth?redirect_uri=${encodeURIComponent(target)}&state=S`,
  );

  const handler = expressBroker(relay);
  const { res, out } = makeRes();
  await handler(
    makeReq(`/oauth-relay/callback?code=abc&state=${encodeURIComponent(state)}`, {
      "x-forwarded-host": "broker.example.com",
      "x-forwarded-proto": "https",
    }),
    res,
  );

  expect(out.status).toBe(302);
  const loc = new URL(out.location ?? "");
  expect(loc.origin + loc.pathname).toBe(target);
  expect(loc.searchParams.get("code")).toBe("abc");
});

test("expressBroker returns 400 on a forged state", async () => {
  const relay = createRelay({ signingKey: SECRET, brokerUrl: BROKER, now: () => 1_000 });
  const handler = expressBroker(relay);
  const { res, out } = makeRes();
  await handler(
    makeReq("/oauth-relay/callback?code=abc&state=garbage", {
      "x-forwarded-host": "broker.example.com",
    }),
    res,
  );
  expect(out.status).toBe(400);
  expect(out.body).toContain("OAuth relay error");
});
