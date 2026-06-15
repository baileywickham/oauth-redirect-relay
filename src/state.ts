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
  /** optional provider's original `state`, preserved through the relay */
  p?: string;
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

  // Decode the signature segment BEFORE calling verify.
  // If the segment is not valid base64url, atob throws and we surface
  // MalformedState immediately — an attacker cannot reach verify or JSON.parse
  // with an unsigned payload.
  let sigBytes: Uint8Array<ArrayBuffer>;
  try {
    sigBytes = base64urlToBytes(sigSegment);
  } catch {
    throw new RelayError("MalformedState", "signature segment is not base64url");
  }

  // Verify the HMAC against the raw body string BEFORE decoding or parsing it.
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes,
    encoder.encode(body),
  );
  if (!valid) throw new RelayError("InvalidSignature", "state signature did not verify");

  // Only reach here if the signature passed — now safe to decode and parse.
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
