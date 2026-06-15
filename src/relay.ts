import { importKey, encodeState, decodeState, type StatePayload } from "./state";
import { isTargetAllowed } from "./allowlist";
import { RelayError, type RelayErrorCode } from "./errors";

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

export interface HandleCallbackInput {
  /** Full incoming request URL at the broker, including query string. */
  url: string;
}

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

  const allowOpts = {
    allowLoopback: options.allowLoopback ?? true,
    allowedOrigins: options.allowedOrigins ?? [],
  };

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

  /** Verify signature + expiry. Throws RelayError on failure. */
  async function verifySignedState(state: string): Promise<StatePayload> {
    const key = await keyPromise;
    const payload = await decodeState(key, state); // throws MalformedState or InvalidSignature
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
      if (err instanceof RelayError) {
        return { status: 400, error: err.code, message: err.message };
      }
      return { status: 400, error: "MalformedState", message: "state verification failed" };
    }

    if (!isTargetAllowed(payload.t, allowOpts)) {
      return { status: 400, error: "TargetNotAllowed", message: `target not allowed: ${payload.t}` };
    }

    const dest = new URL(payload.t);
    // re-attach every param the provider sent back, so success/error params pass through
    for (const [k, v] of incoming.searchParams) dest.searchParams.set(k, v);
    return { status: 302, location: dest.toString() };
  }

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
}
