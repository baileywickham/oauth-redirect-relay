import { test, expect } from "bun:test";
import { createRelay, isRelayState } from "./relay";

const SECRET = "wrap-secret";
const BROKER = "https://broker.example.com/oauth-relay/callback";

function authorizeUrl(target: string, state: string): string {
  const u = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  u.searchParams.set("client_id", "client-x");
  u.searchParams.set("redirect_uri", target);
  u.searchParams.set("state", state);
  u.searchParams.set("scope", "email");
  return u.toString();
}

test("wrapAuthorizeUrl rewrites redirect_uri to the broker and signs the state", async () => {
  const relay = createRelay({ signingKey: SECRET, brokerUrl: BROKER, now: () => 1_000 });
  const target = "http://localhost:3000/google-workspace/callback";

  const { url, state, nonce } = await relay.wrapAuthorizeUrl(
    authorizeUrl(target, "ORIGINAL"),
  );

  const wrapped = new URL(url);
  expect(wrapped.searchParams.get("redirect_uri")).toBe(BROKER);
  expect(wrapped.searchParams.get("state")).toBe(state);
  expect(wrapped.searchParams.get("scope")).toBe("email"); // other params preserved
  expect(isRelayState(state)).toBe(true);
  expect(nonce.length).toBeGreaterThanOrEqual(16);
});

test("full round-trip: wrap → broker handleCallback → verifyReturn recovers provider state", async () => {
  const relay = createRelay({ signingKey: SECRET, brokerUrl: BROKER, now: () => 1_000 });
  const target = "http://localhost:3000/google-workspace/callback";

  const { state, nonce } = await relay.wrapAuthorizeUrl(
    authorizeUrl(target, "ORIGINAL_STATE"),
    { orgId: "org_1" },
  );

  // broker leg
  const cb = await relay.handleCallback({
    url: `${BROKER}?code=auth123&state=${encodeURIComponent(state)}`,
  });
  expect(cb.status).toBe(302);
  if (cb.status !== 302) throw new Error("expected 302");
  const loc = new URL(cb.location);
  expect(loc.origin + loc.pathname).toBe(target);
  expect(loc.searchParams.get("code")).toBe("auth123");

  // dev-box leg
  const result = await relay.verifyReturn({
    url: cb.location,
    expectedNonce: nonce,
  });
  expect(result.target).toBe(target);
  expect(result.providerState).toBe("ORIGINAL_STATE");
  expect(result.data).toEqual({ orgId: "org_1" });
});

test("verifyReturn without expectedNonce enforces signature + expiry only", async () => {
  const relay = createRelay({ signingKey: SECRET, brokerUrl: BROKER, now: () => 1_000 });
  const { url } = await relay.wrapAuthorizeUrl(
    authorizeUrl("http://localhost:3000/cb", "S"),
  );
  const state = new URL(url).searchParams.get("state");
  if (!state) throw new Error("missing state");

  // No nonce supplied → still resolves (sig + exp checked).
  const ok = await relay.verifyReturn({
    url: `http://localhost:3000/cb?code=x&state=${encodeURIComponent(state)}`,
  });
  expect(ok.providerState).toBe("S");
});

test("verifyReturn without expectedNonce still rejects a tampered state", async () => {
  const relay = createRelay({ signingKey: SECRET, brokerUrl: BROKER, now: () => 1_000 });
  const { url } = await relay.wrapAuthorizeUrl(
    authorizeUrl("http://localhost:3000/cb", "S"),
  );
  const state = new URL(url).searchParams.get("state") ?? "";
  const tampered = state.slice(0, -2) + (state.endsWith("aa") ? "bb" : "aa");
  await expect(
    relay.verifyReturn({
      url: `http://localhost:3000/cb?code=x&state=${encodeURIComponent(tampered)}`,
    }),
  ).rejects.toMatchObject({ code: "InvalidSignature" });
});

test("verifyReturn still enforces the nonce when one is supplied", async () => {
  const relay = createRelay({ signingKey: SECRET, brokerUrl: BROKER, now: () => 1_000 });
  const { url } = await relay.wrapAuthorizeUrl(
    authorizeUrl("http://localhost:3000/cb", "S"),
  );
  const state = new URL(url).searchParams.get("state") ?? "";
  await expect(
    relay.verifyReturn({
      url: `http://localhost:3000/cb?code=x&state=${encodeURIComponent(state)}`,
      expectedNonce: "not-the-nonce",
    }),
  ).rejects.toMatchObject({ code: "NonceMismatch" });
});

test("wrapAuthorizeUrl throws without a brokerUrl", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  await expect(
    relay.wrapAuthorizeUrl(authorizeUrl("http://localhost:3000/cb", "S")),
  ).rejects.toThrow(/brokerUrl/);
});

test("isRelayState distinguishes relay tokens from legacy base64url JSON", () => {
  expect(isRelayState("aGVsbG8.c2ln")).toBe(true);
  // legacy state: base64url(JSON) has no "." separator
  const legacy = Buffer.from(JSON.stringify({ a: 1 })).toString("base64url");
  expect(isRelayState(legacy)).toBe(false);
  expect(isRelayState("not a token")).toBe(false);
  expect(isRelayState("a.b.c")).toBe(false);
});
