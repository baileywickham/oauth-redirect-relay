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
