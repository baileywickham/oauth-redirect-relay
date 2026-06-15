import { test, expect } from "bun:test";
import { createRelay, type CallbackOk, type CallbackError } from "./relay";
import { importKey, decodeState } from "./state";

const SECRET = "integration-secret";

test("createState returns a token and a nonce; token decodes to the target+nonce", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  const { state, nonce } = await relay.createState({
    target: "http://localhost:3000/callback",
    data: { provider: "slack" },
  });

  expect(typeof state).toBe("string");
  expect(nonce.length).toBeGreaterThanOrEqual(16);

  const key = await importKey(SECRET);
  const payload = await decodeState(key, state);
  expect(payload.t).toBe("http://localhost:3000/callback");
  expect(payload.n).toBe(nonce);
  expect(payload.d).toEqual({ provider: "slack" });
  expect(payload.x).toBe(1_000 + 600); // default ttlSeconds 600
});

test("ttlSeconds override is reflected in exp", async () => {
  const relay = createRelay({ signingKey: SECRET, ttlSeconds: 30, now: () => 5_000 });
  const { state } = await relay.createState({ target: "http://localhost:9000/cb" });
  const payload = await decodeState(await importKey(SECRET), state);
  expect(payload.x).toBe(5_030);
});

// --- Task 7: handleCallback tests ---

function brokerUrl(state: string, code = "auth-code-123"): string {
  const u = new URL("https://broker.example.com/callback");
  u.searchParams.set("code", code);
  u.searchParams.set("state", state);
  return u.toString();
}

test("handleCallback 302s to the target with code+state re-attached", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  const { state } = await relay.createState({ target: "http://localhost:3000/callback" });

  const result = await relay.handleCallback({ url: brokerUrl(state) });
  expect(result.status).toBe(302);
  const ok = result as CallbackOk;
  const loc = new URL(ok.location);
  expect(loc.origin + loc.pathname).toBe("http://localhost:3000/callback");
  expect(loc.searchParams.get("code")).toBe("auth-code-123");
  expect(loc.searchParams.get("state")).toBe(state);
});

test("handleCallback 400 MissingCode when no code present", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  const { state } = await relay.createState({ target: "http://localhost:3000/callback" });
  const u = new URL("https://broker.example.com/callback");
  u.searchParams.set("state", state);
  const result = (await relay.handleCallback({ url: u.toString() })) as CallbackError;
  expect(result.status).toBe(400);
  expect(result.error).toBe("MissingCode");
});

test("handleCallback 400 Expired when state past its exp", async () => {
  let clock = 1_000;
  const relay = createRelay({ signingKey: SECRET, ttlSeconds: 10, now: () => clock });
  const { state } = await relay.createState({ target: "http://localhost:3000/callback" });
  clock = 2_000; // well past exp 1_010
  const result = (await relay.handleCallback({ url: brokerUrl(state) })) as CallbackError;
  expect(result.status).toBe(400);
  expect(result.error).toBe("Expired");
});

test("handleCallback 400 TargetNotAllowed for a non-allowlisted origin", async () => {
  const relay = createRelay({ signingKey: SECRET, allowLoopback: false, now: () => 1_000 });
  const { state } = await relay.createState({ target: "http://localhost:3000/callback" });
  const result = (await relay.handleCallback({ url: brokerUrl(state) })) as CallbackError;
  expect(result.status).toBe(400);
  expect(result.error).toBe("TargetNotAllowed");
});

test("handleCallback 400 InvalidSignature for a forged state", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  const { state } = await relay.createState({ target: "http://localhost:3000/callback" });
  const forged = state.slice(0, -2) + (state.endsWith("aa") ? "bb" : "aa");
  const result = (await relay.handleCallback({ url: brokerUrl(forged) })) as CallbackError;
  expect(result.status).toBe(400);
  expect(["InvalidSignature", "MalformedState"]).toContain(result.error);
});

test("handleCallback 400 MalformedState when state param missing", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  const u = new URL("https://broker.example.com/callback");
  u.searchParams.set("code", "x");
  const result = (await relay.handleCallback({ url: u.toString() })) as CallbackError;
  expect(result.status).toBe(400);
  expect(result.error).toBe("MalformedState");
});
