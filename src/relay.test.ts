import { test, expect } from "bun:test";
import { createRelay } from "./relay";
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
