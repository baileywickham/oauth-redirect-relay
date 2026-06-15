import { test, expect } from "bun:test";
import { importKey, encodeState, decodeState, type StatePayload } from "./state";
import { RelayError } from "./errors";

const SECRET = "test-signing-secret";

function payload(overrides: Partial<StatePayload> = {}): StatePayload {
  return { t: "http://localhost:3000/callback", n: "nonce-abc", x: 1_000, ...overrides };
}

test("encode then decode round-trips the payload", async () => {
  const key = await importKey(SECRET);
  const token = await encodeState(key, payload({ d: { provider: "slack" } }));
  const decoded = await decodeState(key, token);
  expect(decoded).toEqual(payload({ d: { provider: "slack" } }));
});

test("tampering with the payload fails signature verification", async () => {
  const key = await importKey(SECRET);
  const token = await encodeState(key, payload());
  const [body, sig] = token.split(".");
  const forged = `${body}x.${sig}`;
  await expect(decodeState(key, forged)).rejects.toMatchObject({
    code: "InvalidSignature",
  } satisfies Partial<RelayError>);
});

test("a different key rejects the signature", async () => {
  const key = await importKey(SECRET);
  const otherKey = await importKey("different-secret");
  const token = await encodeState(key, payload());
  await expect(decodeState(otherKey, token)).rejects.toMatchObject({
    code: "InvalidSignature",
  });
});

test("malformed token (no separator) throws MalformedState", async () => {
  const key = await importKey(SECRET);
  await expect(decodeState(key, "not-a-valid-token")).rejects.toMatchObject({
    code: "MalformedState",
  });
});

// Verify-before-parse: the signature segment is base64url-decoded before
// crypto.subtle.verify is called. Characters like % are invalid base64, so
// atob throws immediately — MalformedState is raised without ever reaching
// signature verification or JSON.parse. This keeps the verify-before-parse
// security property intact: an attacker cannot reach JSON.parse with an
// unsigned payload because (a) if the sig segment is unparseable we bail with
// MalformedState before touching verify, and (b) if the sig segment IS valid
// base64url, verify runs and must pass before we parse the payload JSON.
test("non-base64url signature segment throws MalformedState", async () => {
  const key = await importKey(SECRET);
  const token = await encodeState(key, payload());
  const [body] = token.split(".");
  // '%' is not a valid base64 character; atob throws in Bun → MalformedState
  await expect(decodeState(key, `${body}.%%%`)).rejects.toMatchObject({
    code: "MalformedState",
  });
});
