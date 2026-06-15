// node_modules/oauth-redirect-relay/dist/index.js
function bytesToBase64url(bytes) {
  let binary = "";
  for (const b of bytes)
    binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++)
    bytes[i] = binary.charCodeAt(i);
  return bytes;
}
var RelayError = class extends Error {
  code;
  constructor(code, message) {
    super(message);
    this.name = "RelayError";
    this.code = code;
  }
};
var encoder = new TextEncoder();
var decoder = new TextDecoder();
async function importKey(secret) {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function encodeState(key, payload) {
  const body = bytesToBase64url(encoder.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  return `${body}.${bytesToBase64url(new Uint8Array(sig))}`;
}
async function decodeState(key, token) {
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) {
    throw new RelayError("MalformedState", "state is not a <body>.<sig> token");
  }
  const body = token.slice(0, dot);
  const sigSegment = token.slice(dot + 1);
  let sigBytes;
  try {
    sigBytes = base64urlToBytes(sigSegment);
  } catch {
    throw new RelayError("MalformedState", "signature segment is not base64url");
  }
  const valid = await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(body));
  if (!valid)
    throw new RelayError("InvalidSignature", "state signature did not verify");
  let json;
  try {
    json = decoder.decode(base64urlToBytes(body));
  } catch {
    throw new RelayError("MalformedState", "payload segment is not base64url");
  }
  try {
    return JSON.parse(json);
  } catch {
    throw new RelayError("MalformedState", "payload is not valid JSON");
  }
}
var LOOPBACK_HOSTS = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "[::1]"]);
function isTargetAllowed(target, opts) {
  let url;
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
function realNow() {
  return Math.floor(Date.now() / 1e3);
}
async function resolveKey(signingKey) {
  return typeof signingKey === "string" ? importKey(signingKey) : signingKey;
}
function newNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function createRelay(options) {
  const ttlSeconds = options.ttlSeconds ?? 600;
  const now = options.now ?? realNow;
  const keyPromise = resolveKey(options.signingKey);
  const allowOpts = {
    allowLoopback: options.allowLoopback ?? true,
    allowedOrigins: options.allowedOrigins ?? []
  };
  async function createState(input) {
    const key = await keyPromise;
    const nonce = newNonce();
    const payload = {
      t: input.target,
      n: nonce,
      x: now() + ttlSeconds,
      ...input.data !== void 0 ? { d: input.data } : {}
    };
    const state = await encodeState(key, payload);
    return { state, nonce };
  }
  async function verifySignedState(state) {
    const key = await keyPromise;
    const payload = await decodeState(key, state);
    if (now() >= payload.x) {
      throw new RelayError("Expired", "state has expired");
    }
    return payload;
  }
  async function handleCallback(input) {
    let incoming;
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
    let payload;
    try {
      payload = await verifySignedState(state);
    } catch (err) {
      if (err instanceof RelayError) {
        return { status: 400, error: err.code, message: err.message };
      }
      return { status: 400, error: "MalformedState", message: "state verification failed" };
    }
    if (!isTargetAllowed(payload.t, allowOpts)) {
      return { status: 400, error: "TargetNotAllowed", message: `target not allowed: ${payload.t}` };
    }
    const dest = new URL(payload.t);
    for (const [k, v] of incoming.searchParams)
      dest.searchParams.set(k, v);
    return { status: 302, location: dest.toString() };
  }
  async function verifyReturn(input) {
    let incoming;
    try {
      incoming = new URL(input.url);
    } catch {
      throw new RelayError("MalformedState", "callback url is not a url");
    }
    const state = incoming.searchParams.get("state");
    if (!state)
      throw new RelayError("MalformedState", "missing state param");
    const payload = await verifySignedState(state);
    if (payload.n !== input.expectedNonce) {
      throw new RelayError("NonceMismatch", "state nonce did not match stored nonce");
    }
    return { target: payload.t, data: payload.d };
  }
  return { createState, handleCallback, verifyReturn };
}

// src/index.mjs
var relay = createRelay({
  signingKey: process.env.RELAY_SIGNING_KEY,
  allowLoopback: process.env.ALLOW_LOOPBACK !== "false",
  allowedOrigins: (process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean),
  ttlSeconds: Number(process.env.TTL_SECONDS || "600")
});
var handler = async (event) => {
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
    body: `OAuth relay error: ${result.error} \u2014 ${result.message}`
  };
};
export {
  handler
};
