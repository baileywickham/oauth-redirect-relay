# oauth-redirect-relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a framework-agnostic TypeScript library that implements the signed-state OAuth broker pattern, letting many dev boxes share one registered HTTPS redirect URI safely, plus an example Bun broker server.

**Architecture:** A single `createRelay({ signingKey, ttlSeconds, allowLoopback, allowedOrigins })` factory exposes three async methods. `createState` (dev box) signs a compact base64url payload `{ t, n, x, d }` with HMAC-SHA256 via Web Crypto. `handleCallback` (broker) verifies the signature + expiry, checks the target origin against an allowlist, and returns a 302/400 instruction without owning an HTTP server. `verifyReturn` (dev box) re-verifies signature/expiry and matches the CSRF nonce. All time comes from an injectable `now()` clock so tests are deterministic.

**Tech Stack:** TypeScript, Web Crypto (`crypto.subtle`, HMAC-SHA256), Bun (runtime + `bun test` + bundler). No runtime dependencies.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `package.json` | Package metadata, scripts (`test`, `build`), type:module |
| `tsconfig.json` | Strict TS config targeting ESNext/Web Crypto |
| `src/errors.ts` | Typed error classes + error-code union |
| `src/base64url.ts` | base64url encode/decode of bytes ↔ string |
| `src/state.ts` | Payload type, HMAC sign/verify, encode/decode of signed state |
| `src/allowlist.ts` | Origin allow check (loopback default + explicit origins) |
| `src/relay.ts` | `createRelay` factory + `createState`/`handleCallback`/`verifyReturn` |
| `src/index.ts` | Public exports |
| `examples/broker.ts` | Runnable Bun broker server using the library |
| `src/*.test.ts` | Colocated unit tests |
| `examples/broker.test.ts` | Broker smoke test |

Each `src` file has one responsibility and is independently testable. `relay.ts` composes `state`, `allowlist`, and `errors`; it holds no crypto or parsing logic itself.

---

## Task 1: Project scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`

- [ ] **Step 1: Write package.json**

```json
{
  "name": "oauth-redirect-relay",
  "version": "0.1.0",
  "description": "Signed-state OAuth broker pattern: share one registered redirect URI across many dev boxes, safely.",
  "type": "module",
  "main": "./dist/index.js",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  },
  "files": ["dist"],
  "sideEffects": false,
  "keywords": ["oauth", "redirect-uri", "slack", "csrf", "hmac", "broker", "localhost", "dev"],
  "scripts": {
    "test": "bun test",
    "build": "bun build src/index.ts --outdir dist --target node && tsc -p tsconfig.build.json",
    "typecheck": "tsc --noEmit",
    "prepublishOnly": "bun run typecheck && bun test && bun run build"
  },
  "publishConfig": {
    "access": "public"
  },
  "license": "MIT",
  "devDependencies": {
    "typescript": "^5.6.0",
    "@types/bun": "latest"
  }
}
```

Entry points target built `dist/` so npm consumers get compiled JS + `.d.ts`, while the
tests and the example import from `src/` via relative paths (never through the package
name), so local development still runs straight off TypeScript. `prepublishOnly` gates
every publish on a clean typecheck, green tests, and a fresh build. `files: ["dist"]` keeps
`src/` and tests out of the tarball.

- [ ] **Step 2: Write tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ESNext", "DOM"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "declaration": true,
    "skipLibCheck": true,
    "types": ["bun"],
    "verbatimModuleSyntax": true
  },
  "include": ["src", "examples"]
}
```

The `DOM` lib provides Web Crypto (`crypto.subtle`, `CryptoKey`) types.

- [ ] **Step 3: Write tsconfig.build.json**

A separate config for declaration emit so only `src` (minus tests) lands in `dist`. The
main `tsconfig.json` still includes `examples` for editor/typecheck, but the published
build must not ship example or test `.d.ts`.

```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "emitDeclarationOnly": true,
    "outDir": "dist",
    "noEmit": false
  },
  "include": ["src"],
  "exclude": ["src/**/*.test.ts"]
}
```

- [ ] **Step 4: Install dev deps**

Run: `bun install`
Expected: creates `bun.lockb`, installs typescript + @types/bun, no errors.

- [ ] **Step 5: Commit**

```bash
git add package.json tsconfig.json tsconfig.build.json bun.lockb
git commit -m "chore: scaffold oauth-redirect-relay package"
```

---

## Task 2: Typed errors

**Files:**
- Create: `src/errors.ts`
- Test: `src/errors.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/errors.test.ts
import { test, expect } from "bun:test";
import { RelayError, type RelayErrorCode } from "./errors";

test("RelayError carries a typed code and is instanceof Error", () => {
  const err = new RelayError("Expired", "state has expired");
  expect(err).toBeInstanceOf(Error);
  expect(err).toBeInstanceOf(RelayError);
  expect(err.code).toBe("Expired");
  expect(err.message).toBe("state has expired");
  expect(err.name).toBe("RelayError");
});

test("error codes are usable as a discriminant", () => {
  const codes: RelayErrorCode[] = [
    "MalformedState",
    "InvalidSignature",
    "Expired",
    "NonceMismatch",
    "TargetNotAllowed",
    "MissingCode",
  ];
  expect(codes.length).toBe(6);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/errors.test.ts`
Expected: FAIL — cannot find module `./errors`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/errors.ts
export type RelayErrorCode =
  | "MalformedState"
  | "InvalidSignature"
  | "Expired"
  | "NonceMismatch"
  | "TargetNotAllowed"
  | "MissingCode";

export class RelayError extends Error {
  readonly code: RelayErrorCode;

  constructor(code: RelayErrorCode, message: string) {
    super(message);
    this.name = "RelayError";
    this.code = code;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/errors.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/errors.ts src/errors.test.ts
git commit -m "feat: typed RelayError with error-code union"
```

---

## Task 3: base64url codec

**Files:**
- Create: `src/base64url.ts`
- Test: `src/base64url.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/base64url.test.ts
import { test, expect } from "bun:test";
import { bytesToBase64url, base64urlToBytes } from "./base64url";

test("round-trips arbitrary bytes", () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  const encoded = bytesToBase64url(bytes);
  expect(base64urlToBytes(encoded)).toEqual(bytes);
});

test("produces url-safe output with no padding", () => {
  // 0xfb 0xff would be "+/" in standard base64; url-safe uses "-_"
  const encoded = bytesToBase64url(new Uint8Array([0xfb, 0xff, 0xbf]));
  expect(encoded).not.toContain("+");
  expect(encoded).not.toContain("/");
  expect(encoded).not.toContain("=");
});

test("decodes input that lacks padding", () => {
  const encoded = bytesToBase64url(new Uint8Array([1, 2, 3]));
  expect(base64urlToBytes(encoded)).toEqual(new Uint8Array([1, 2, 3]));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/base64url.test.ts`
Expected: FAIL — cannot find module `./base64url`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/base64url.ts
export function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
```

`atob` tolerates missing padding in Bun/Node/browsers, so no manual re-padding is needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/base64url.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/base64url.ts src/base64url.test.ts
git commit -m "feat: url-safe base64 codec"
```

---

## Task 4: Signed state codec

**Files:**
- Create: `src/state.ts`
- Test: `src/state.test.ts`

This module owns the HMAC and the wire format. The signed token is two base64url
segments joined by `.`: `<payloadB64>.<sigB64>`.

- [ ] **Step 1: Write the failing test**

```ts
// src/state.test.ts
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
  // flip the payload but keep the old signature
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

test("non-JSON payload throws MalformedState", async () => {
  const key = await importKey(SECRET);
  // sign garbage bytes so the signature passes but JSON.parse fails
  const token = await encodeState(key, payload());
  const [, sig] = token.split(".");
  // craft body that is valid base64url but not JSON, re-sign is hard; instead
  // assert decode of a body that passes structure but bad content path:
  // use a body of "%%%" which base64urlToBytes/atob will reject -> MalformedState
  await expect(decodeState(key, `%%%.${sig}`)).rejects.toMatchObject({
    code: "MalformedState",
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/state.test.ts`
Expected: FAIL — cannot find module `./state`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/state.ts
import { bytesToBase64url, base64urlToBytes } from "./base64url";
import { RelayError } from "./errors";

export interface StatePayload {
  /** target redirect URL the broker bounces back to */
  t: string;
  /** CSRF nonce, validated by the dev box */
  n: string;
  /** expiry, unix seconds */
  x: number;
  /** optional signed passthrough data */
  d?: unknown;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Import a raw secret string as an HMAC-SHA256 CryptoKey (sign + verify). */
export async function importKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function encodeState(key: CryptoKey, payload: StatePayload): Promise<string> {
  const body = bytesToBase64url(encoder.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  return `${body}.${bytesToBase64url(new Uint8Array(sig))}`;
}

export async function decodeState(key: CryptoKey, token: string): Promise<StatePayload> {
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) {
    throw new RelayError("MalformedState", "state is not a <body>.<sig> token");
  }
  const body = token.slice(0, dot);
  const sigSegment = token.slice(dot + 1);

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64urlToBytes(sigSegment);
  } catch {
    throw new RelayError("MalformedState", "signature segment is not base64url");
  }

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes,
    encoder.encode(body),
  );
  if (!valid) throw new RelayError("InvalidSignature", "state signature did not verify");

  let json: string;
  try {
    json = decoder.decode(base64urlToBytes(body));
  } catch {
    throw new RelayError("MalformedState", "payload segment is not base64url");
  }

  try {
    return JSON.parse(json) as StatePayload;
  } catch {
    throw new RelayError("MalformedState", "payload is not valid JSON");
  }
}
```

Note the verification order: signature is checked **before** the body is parsed, so an
attacker cannot reach `JSON.parse` with an unsigned payload. The `%%%` test case is
rejected at the signature step (the forged body changes the signed input), and a malformed
*signature segment* is caught by the base64url try/catch.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/state.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/state.ts src/state.test.ts
git commit -m "feat: HMAC-signed state codec with verify-before-parse"
```

---

## Task 5: Allowlist

**Files:**
- Create: `src/allowlist.ts`
- Test: `src/allowlist.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/allowlist.test.ts
import { test, expect } from "bun:test";
import { isTargetAllowed } from "./allowlist";

test("mode A: loopback allowed on any port by default", () => {
  const opts = { allowLoopback: true, allowedOrigins: [] };
  expect(isTargetAllowed("http://localhost:3000/callback", opts)).toBe(true);
  expect(isTargetAllowed("http://127.0.0.1:55123/cb", opts)).toBe(true);
});

test("mode A: non-loopback rejected unless explicitly listed", () => {
  const opts = { allowLoopback: true, allowedOrigins: ["https://alice.dev.example.com"] };
  expect(isTargetAllowed("https://alice.dev.example.com/callback", opts)).toBe(true);
  expect(isTargetAllowed("https://evil.example.com/callback", opts)).toBe(false);
});

test("mode B: allowLoopback false rejects localhost", () => {
  const opts = { allowLoopback: false, allowedOrigins: ["https://alice.dev.example.com"] };
  expect(isTargetAllowed("http://localhost:3000/callback", opts)).toBe(false);
  expect(isTargetAllowed("https://alice.dev.example.com/x", opts)).toBe(true);
});

test("origin match is on scheme+host+port, not substring", () => {
  const opts = { allowLoopback: false, allowedOrigins: ["https://alice.dev.example.com"] };
  // attacker host that merely contains the allowed string
  expect(isTargetAllowed("https://alice.dev.example.com.evil.com/x", opts)).toBe(false);
  // wrong scheme
  expect(isTargetAllowed("http://alice.dev.example.com/x", opts)).toBe(false);
});

test("unparseable url is rejected", () => {
  const opts = { allowLoopback: true, allowedOrigins: [] };
  expect(isTargetAllowed("not a url", opts)).toBe(false);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/allowlist.test.ts`
Expected: FAIL — cannot find module `./allowlist`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/allowlist.ts
export interface AllowlistOptions {
  allowLoopback: boolean;
  allowedOrigins: string[];
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function isTargetAllowed(target: string, opts: AllowlistOptions): boolean {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return false;
  }

  if (opts.allowLoopback && url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) {
    return true;
  }

  return opts.allowedOrigins.some((allowed) => {
    try {
      return new URL(allowed).origin === url.origin;
    } catch {
      return false;
    }
  });
}
```

`url.hostname` for an IPv6 loopback is `[::1]`, which is why it is in the set. Loopback is
intentionally restricted to `http:` since that is what a local dev server speaks.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/allowlist.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/allowlist.ts src/allowlist.test.ts
git commit -m "feat: origin allowlist with loopback default"
```

---

## Task 6: createRelay — createState

**Files:**
- Create: `src/relay.ts`
- Test: `src/relay.test.ts`

`createRelay` returns an object with the three methods. We build it across Tasks 6–8,
adding one method per task to the same file. The factory accepts an injectable `now()`
clock (defaulting to real time) so expiry tests are deterministic.

- [ ] **Step 1: Write the failing test**

```ts
// src/relay.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/relay.test.ts`
Expected: FAIL — cannot find module `./relay`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/relay.ts
import { importKey, encodeState, type StatePayload } from "./state";

export interface CreateRelayOptions {
  /** HMAC-SHA256 secret shared by dev box + broker. */
  signingKey: string | CryptoKey;
  /** Signed lifetime of a state, in seconds. Default 600. */
  ttlSeconds?: number;
  /** mode A default true: localhost/127.0.0.1 (any port) allowed. */
  allowLoopback?: boolean;
  /** Extra exact origins allowed as redirect targets. */
  allowedOrigins?: string[];
  /** Injectable clock returning unix seconds. Default real time. */
  now?: () => number;
}

export interface CreateStateInput {
  target: string;
  data?: unknown;
}

export interface CreateStateResult {
  state: string;
  nonce: string;
}

function realNow(): number {
  return Math.floor(Date.now() / 1000);
}

async function resolveKey(signingKey: string | CryptoKey): Promise<CryptoKey> {
  return typeof signingKey === "string" ? importKey(signingKey) : signingKey;
}

function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function createRelay(options: CreateRelayOptions) {
  const ttlSeconds = options.ttlSeconds ?? 600;
  const now = options.now ?? realNow;
  const keyPromise = resolveKey(options.signingKey);

  async function createState(input: CreateStateInput): Promise<CreateStateResult> {
    const key = await keyPromise;
    const nonce = newNonce();
    const payload: StatePayload = {
      t: input.target,
      n: nonce,
      x: now() + ttlSeconds,
      ...(input.data !== undefined ? { d: input.data } : {}),
    };
    const state = await encodeState(key, payload);
    return { state, nonce };
  }

  return { createState };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/relay.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/relay.ts src/relay.test.ts
git commit -m "feat: createRelay.createState"
```

---

## Task 7: handleCallback (broker side)

**Files:**
- Modify: `src/relay.ts`
- Test: `src/relay.test.ts` (add cases)

`handleCallback` parses `state` + `code` from the incoming broker URL, verifies the
signed state (signature + expiry), checks the target against the allowlist, then returns a
302 to the target with the original `code` and `state` re-attached. Any failure returns a
400 with a typed code — never a redirect.

- [ ] **Step 1: Write the failing test (append to src/relay.test.ts)**

```ts
import { CallbackOk, CallbackError } from "./relay";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/relay.test.ts`
Expected: FAIL — `handleCallback` / `CallbackOk` / `CallbackError` not exported.

- [ ] **Step 3: Write minimal implementation**

Add the types and the method. Replace the import line and the `return { createState }`
line in `src/relay.ts`:

Change the top import to also pull in `decodeState`, `isTargetAllowed`, and `RelayError`:

```ts
import { importKey, encodeState, decodeState, type StatePayload } from "./state";
import { isTargetAllowed } from "./allowlist";
import { RelayError, type RelayErrorCode } from "./errors";
```

Add these exported types above `createRelay`:

```ts
export interface HandleCallbackInput {
  /** Full incoming request URL at the broker, including query string. */
  url: string;
}

export interface CallbackOk {
  status: 302;
  location: string;
}

export interface CallbackError {
  status: 400;
  error: RelayErrorCode;
  message: string;
}

export type CallbackResult = CallbackOk | CallbackError;
```

Inside `createRelay`, after `createState`, add `handleCallback` and a shared verify helper,
then return both methods:

```ts
  const allowOpts = {
    allowLoopback: options.allowLoopback ?? true,
    allowedOrigins: options.allowedOrigins ?? [],
  };

  /** Verify signature + expiry. Throws RelayError on failure. */
  async function verifySignedState(state: string): Promise<StatePayload> {
    const key = await keyPromise;
    const payload = await decodeState(key, state); // throws Malformed/InvalidSignature
    if (now() >= payload.x) {
      throw new RelayError("Expired", "state has expired");
    }
    return payload;
  }

  async function handleCallback(input: HandleCallbackInput): Promise<CallbackResult> {
    let incoming: URL;
    try {
      incoming = new URL(input.url);
    } catch {
      return { status: 400, error: "MalformedState", message: "request url is not a url" };
    }

    const state = incoming.searchParams.get("state");
    const code = incoming.searchParams.get("code");
    if (!state) {
      return { status: 400, error: "MalformedState", message: "missing state param" };
    }
    if (!code) {
      return { status: 400, error: "MissingCode", message: "missing code param" };
    }

    let payload: StatePayload;
    try {
      payload = await verifySignedState(state);
    } catch (err) {
      const e = err as RelayError;
      return { status: 400, error: e.code, message: e.message };
    }

    if (!isTargetAllowed(payload.t, allowOpts)) {
      return { status: 400, error: "TargetNotAllowed", message: `target not allowed: ${payload.t}` };
    }

    const dest = new URL(payload.t);
    // re-attach every param the provider sent back, so success/error params pass through
    for (const [k, v] of incoming.searchParams) dest.searchParams.set(k, v);
    return { status: 302, location: dest.toString() };
  }

  return { createState, handleCallback };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/relay.test.ts`
Expected: PASS (8 tests: 2 from Task 6 + 6 new).

- [ ] **Step 5: Commit**

```bash
git add src/relay.ts src/relay.test.ts
git commit -m "feat: createRelay.handleCallback with allowlist + expiry guards"
```

---

## Task 8: verifyReturn (dev box completion)

**Files:**
- Modify: `src/relay.ts`
- Test: `src/relay.test.ts` (add cases)

`verifyReturn` runs on the dev box when its localhost callback is hit. It re-verifies the
signed state (signature + expiry) and checks the nonce against the value the dev box
stored at `createState` time. Returns `{ target, data }` or throws a typed `RelayError`.

- [ ] **Step 1: Write the failing test (append to src/relay.test.ts)**

```ts
function localhostUrl(state: string, code = "auth-code-123"): string {
  const u = new URL("http://localhost:3000/callback");
  u.searchParams.set("code", code);
  u.searchParams.set("state", state);
  return u.toString();
}

test("verifyReturn returns target+data when nonce matches", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  const { state, nonce } = await relay.createState({
    target: "http://localhost:3000/callback",
    data: { provider: "slack" },
  });

  const result = await relay.verifyReturn({
    url: localhostUrl(state),
    expectedNonce: nonce,
  });
  expect(result.target).toBe("http://localhost:3000/callback");
  expect(result.data).toEqual({ provider: "slack" });
});

test("verifyReturn throws NonceMismatch on wrong nonce", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  const { state } = await relay.createState({ target: "http://localhost:3000/callback" });
  await expect(
    relay.verifyReturn({ url: localhostUrl(state), expectedNonce: "not-the-nonce" }),
  ).rejects.toMatchObject({ code: "NonceMismatch" });
});

test("verifyReturn throws Expired past exp", async () => {
  let clock = 1_000;
  const relay = createRelay({ signingKey: SECRET, ttlSeconds: 10, now: () => clock });
  const { state, nonce } = await relay.createState({ target: "http://localhost:3000/callback" });
  clock = 2_000;
  await expect(
    relay.verifyReturn({ url: localhostUrl(state), expectedNonce: nonce }),
  ).rejects.toMatchObject({ code: "Expired" });
});

test("verifyReturn throws MalformedState when state param absent", async () => {
  const relay = createRelay({ signingKey: SECRET, now: () => 1_000 });
  await expect(
    relay.verifyReturn({ url: "http://localhost:3000/callback?code=x", expectedNonce: "n" }),
  ).rejects.toMatchObject({ code: "MalformedState" });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/relay.test.ts`
Expected: FAIL — `verifyReturn` not a function.

- [ ] **Step 3: Write minimal implementation**

Add exported types above `createRelay`:

```ts
export interface VerifyReturnInput {
  /** Full URL the dev-box localhost callback was hit with. */
  url: string;
  /** Nonce the dev box stored when it called createState. */
  expectedNonce: string;
}

export interface VerifyReturnResult {
  target: string;
  data: unknown;
}
```

Inside `createRelay`, add `verifyReturn` and include it in the returned object:

```ts
  async function verifyReturn(input: VerifyReturnInput): Promise<VerifyReturnResult> {
    let incoming: URL;
    try {
      incoming = new URL(input.url);
    } catch {
      throw new RelayError("MalformedState", "callback url is not a url");
    }
    const state = incoming.searchParams.get("state");
    if (!state) throw new RelayError("MalformedState", "missing state param");

    const payload = await verifySignedState(state); // throws Malformed/InvalidSignature/Expired
    if (payload.n !== input.expectedNonce) {
      throw new RelayError("NonceMismatch", "state nonce did not match stored nonce");
    }
    return { target: payload.t, data: payload.d };
  }

  return { createState, handleCallback, verifyReturn };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/relay.test.ts`
Expected: PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
git add src/relay.ts src/relay.test.ts
git commit -m "feat: createRelay.verifyReturn with nonce CSRF check"
```

---

## Task 9: Public exports

**Files:**
- Create: `src/index.ts`
- Test: `src/index.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/index.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/index.test.ts`
Expected: FAIL — cannot find module `./index`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/index.ts
export { createRelay } from "./relay";
export type {
  CreateRelayOptions,
  CreateStateInput,
  CreateStateResult,
  HandleCallbackInput,
  CallbackOk,
  CallbackError,
  CallbackResult,
  VerifyReturnInput,
  VerifyReturnResult,
} from "./relay";
export { RelayError } from "./errors";
export type { RelayErrorCode } from "./errors";
export type { StatePayload } from "./state";
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/index.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Typecheck the whole package**

Run: `bun run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "feat: public exports"
```

---

## Task 10: Example Bun broker server + smoke test

**Files:**
- Create: `examples/broker.ts`
- Test: `examples/broker.test.ts`

The example is a real `Bun.serve` broker: it reads the signing key from `RELAY_SIGNING_KEY`,
handles `GET /callback` via `handleCallback`, and returns a 302 or a 400 page. It is the
deployable artifact (e.g. to a tunnel or edge host) holding the one registered redirect URI.

- [ ] **Step 1: Write the failing test**

```ts
// examples/broker.test.ts
import { test, expect, beforeAll, afterAll } from "bun:test";
import { createRelay } from "../src/index";

const SECRET = "example-secret";
let server: ReturnType<typeof import("./broker").startBroker>;
let base: string;

beforeAll(() => {
  const mod = require("./broker");
  server = mod.startBroker({ signingKey: SECRET, port: 0 });
  base = `http://localhost:${server.port}`;
});

afterAll(() => server.stop());

test("valid state 302s to the localhost target", async () => {
  const relay = createRelay({ signingKey: SECRET });
  const { state } = await relay.createState({ target: "http://localhost:3000/callback" });
  const res = await fetch(
    `${base}/callback?code=abc&state=${encodeURIComponent(state)}`,
    { redirect: "manual" },
  );
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location")!);
  expect(loc.origin + loc.pathname).toBe("http://localhost:3000/callback");
  expect(loc.searchParams.get("code")).toBe("abc");
});

test("forged state returns 400", async () => {
  const res = await fetch(`${base}/callback?code=abc&state=garbage`, { redirect: "manual" });
  expect(res.status).toBe(400);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test examples/broker.test.ts`
Expected: FAIL — cannot find module `./broker`.

- [ ] **Step 3: Write minimal implementation**

```ts
// examples/broker.ts
import { createRelay, type CallbackOk } from "../src/index";

export interface StartBrokerOptions {
  signingKey: string;
  /** Port to listen on. Use 0 for an ephemeral port (tests). */
  port?: number;
  /** Extra non-loopback origins to allow. */
  allowedOrigins?: string[];
}

export function startBroker(opts: StartBrokerOptions) {
  const relay = createRelay({
    signingKey: opts.signingKey,
    allowedOrigins: opts.allowedOrigins ?? [],
  });

  return Bun.serve({
    port: opts.port ?? 8787,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname !== "/callback") {
        return new Response("not found", { status: 404 });
      }

      const result = await relay.handleCallback({ url: req.url });
      if (result.status === 302) {
        return new Response(null, {
          status: 302,
          headers: { location: (result as CallbackOk).location },
        });
      }
      return new Response(`OAuth relay error: ${result.error} — ${result.message}`, {
        status: 400,
      });
    },
  });
}

// Run directly: `RELAY_SIGNING_KEY=... bun examples/broker.ts`
if (import.meta.main) {
  const signingKey = process.env.RELAY_SIGNING_KEY;
  if (!signingKey) {
    console.error("set RELAY_SIGNING_KEY");
    process.exit(1);
  }
  const server = startBroker({ signingKey });
  console.log(`broker listening on http://localhost:${server.port}/callback`);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test examples/broker.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the full suite**

Run: `bun test`
Expected: all tests pass across every file.

- [ ] **Step 6: Commit**

```bash
git add examples/broker.ts examples/broker.test.ts
git commit -m "feat: example Bun broker server + smoke test"
```

---

## Task 11: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write the README**

Document, with copy-pasteable code: the problem (Slack-style exact-match redirect URIs +
no localhost/wildcards), the three-step flow (dev box `createState` → broker
`handleCallback` → dev box `verifyReturn`), the `createRelay` options table (`signingKey`,
`ttlSeconds`, `allowLoopback`, `allowedOrigins`), mode A vs mode B allowlist examples, how
to run the example broker (`RELAY_SIGNING_KEY=... bun examples/broker.ts`), and a security
note: this library does the signed-state + allowlist + nonce; the app still owns PKCE and
the token exchange.

Content:

````markdown
# oauth-redirect-relay

Share **one** registered OAuth redirect URI across many dev boxes — safely.

OAuth providers match redirect URIs by exact string, and some (Slack) reject
`http://localhost` and forbid wildcards. Instead of registering every dev machine,
register one HTTPS broker URL, sign the real dev-box target into the OAuth `state`, and let
a tiny broker verify it and bounce the `code` back to the right machine.

This library gives you the signed-state codec, the broker verification (with an origin
allowlist that prevents open redirects), and a CSRF nonce. It does **not** do PKCE or the
token exchange — that stays in your app's OAuth client.

## Install

```bash
bun add oauth-redirect-relay
```

## Flow

```ts
import { createRelay } from "oauth-redirect-relay";

const relay = createRelay({ signingKey: process.env.RELAY_SIGNING_KEY! });

// 1. dev box: start the flow
const { state, nonce } = await relay.createState({
  target: "http://localhost:3000/callback",
  data: { provider: "slack" },
});
// store `nonce` (cookie), send user to the provider with
//   redirect_uri = <BROKER_URL>,  state = <state>

// 2. broker (the one registered HTTPS callback)
const result = await relay.handleCallback({ url: req.url });
// → { status: 302, location } | { status: 400, error, message }

// 3. dev box: finish the flow at your localhost callback
const { target, data } = await relay.verifyReturn({
  url: req.url,
  expectedNonce: storedNonce,
});
// then do your own token exchange with the `code`
```

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `signingKey` | — | HMAC-SHA256 secret (string) or `CryptoKey`, shared by dev box + broker |
| `ttlSeconds` | `600` | Signed lifetime of a state |
| `allowLoopback` | `true` | Allow `http://localhost` / `127.0.0.1` on any port (mode A) |
| `allowedOrigins` | `[]` | Extra exact origins allowed as targets |

Mode B (lock down, no loopback): `allowLoopback: false` + an explicit `allowedOrigins` list.

## Example broker

```bash
RELAY_SIGNING_KEY=your-secret bun examples/broker.ts
```

## Security notes

- The allowlist is what stops this from being an open redirect — keep `allowLoopback: false`
  in any non-dev deployment and list exact origins.
- The signing key is shared by both sides; use a dev-only key, never your prod app secret.
- This library covers signed state + allowlist + nonce. Use PKCE in your OAuth client too.
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README with usage, options, and security notes"
```

---

## Task 12: Publish to npm

**Files:** none (publishing the existing build).

Publishing to public npm under the unscoped name `oauth-redirect-relay`. This task is run
manually once the package is green; it is not a code change.

- [ ] **Step 1: Confirm the name is available**

Run: `npm view oauth-redirect-relay version`
Expected: `npm error 404` (name unclaimed). If it returns a version, the name is taken —
pick a scoped name (`@<your-npm-user>/oauth-redirect-relay`), update `package.json` `name`,
and keep `publishConfig.access: "public"`.

- [ ] **Step 2: Verify you are logged in**

Run: `npm whoami`
Expected: prints your npm username. If not, run `npm login` (interactive — run it yourself
in the terminal).

- [ ] **Step 3: Inspect the tarball contents**

Run: `npm pack --dry-run`
Expected: the file list contains only `dist/index.js`, `dist/index.d.ts`, `package.json`,
`README.md`, `LICENSE` (if present) — and **no** `src/`, `*.test.ts`, or `examples/`.
`prepublishOnly` runs typecheck + tests + build first; all must pass.

- [ ] **Step 4: Publish**

Run: `npm publish`
Expected: `+ oauth-redirect-relay@0.1.0`. (`publishConfig.access: "public"` makes this work
even if you later switch to a scoped name.)

- [ ] **Step 5: Verify the published package**

Run: `npm view oauth-redirect-relay`
Expected: shows version `0.1.0` and the `dist`-based entry points.

---

## Self-Review Notes

- **Spec coverage:** factory + 3 methods (Tasks 6–8), Web Crypto HMAC (Task 4), base64url
  compact format (Task 3), nonce + exp + passthrough (Tasks 6/8), typed errors + no-302-on-
  failure (Tasks 2/7), loopback default + explicit allowlist modes A/B (Task 5), injectable
  clock for deterministic expiry tests (Tasks 6–8), example Bun broker + smoke test (Task
  10), module layout matches the spec's `src/` list (all tasks), PKCE/token-exchange
  explicitly out of scope (README + no task). All spec sections map to a task.
- **Publish-readiness:** package entry points target built `dist/` with `files: ["dist"]`,
  a build-only tsconfig keeps tests/examples out of the tarball, `prepublishOnly` gates on
  typecheck+tests+build, and Task 12 covers name-availability, `npm pack` inspection, and
  publish for public unscoped npm.
- **Type consistency:** `StatePayload` fields `{ t, n, x, d }` used identically in Tasks 4,
  6, 7, 8. `CallbackOk.location` / `CallbackError.error` consistent across Tasks 7, 9, 10.
  `verifySignedState` defined in Task 7 and reused in Task 8.
- **Placeholders:** none — every code step has complete code.
