import { test, expect } from "bun:test";
import * as lib from "./index";

test("public surface is exported", () => {
  expect(typeof lib.createRelay).toBe("function");
  expect(typeof lib.RelayError).toBe("function");
});

test("createRelay from the index produces a working round-trip", async () => {
  const relay = lib.createRelay({ signingKey: "s", now: () => 1_000 });
  const { state, nonce } = await relay.createState({ target: "http://localhost:3000/cb" });
  const cb = await relay.handleCallback({
    url: `https://broker/cb?code=c&state=${encodeURIComponent(state)}`,
  });
  expect(cb.status).toBe(302);
  const ret = await relay.verifyReturn({
    url: (cb as lib.CallbackOk).location,
    expectedNonce: nonce,
  });
  expect(ret.target).toBe("http://localhost:3000/cb");
});
