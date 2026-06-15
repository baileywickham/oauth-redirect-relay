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
  /**
   * The hosted broker callback URL registered with the OAuth provider. Required
   * to use `wrapAuthorizeUrl`; unused by the broker itself.
   */
  brokerUrl?: string;
  /** Injectable clock returning unix seconds. Default real time. */
  now?: () => number;
}

export interface CreateStateInput {
  target: string;
  data?: unknown;
  /** The provider's original `state`, to preserve through the relay. */
  providerState?: string;
}

export interface CreateStateResult {
  state: string;
  nonce: string;
}

export interface WrapAuthorizeUrlResult {
  /** The authorize URL rewritten to route through the broker. */
  url: string;
  /** The signed relay state (also embedded in `url`). */
  state: string;
  /** The CSRF nonce to stash (e.g. a cookie) and pass to `verifyReturn`. */
  nonce: string;
}

export interface HandleCallbackInput {
  /** Full incoming request URL at the broker, including query string. */
  url: string;
}

export interface VerifyReturnInput {
  /** Full URL the dev-box localhost callback was hit with. */
  url: string;
  /**
   * Nonce the dev box stored when it created the state. When omitted, the nonce
   * check is skipped (signature + expiry are still enforced) — use this for
   * server-initiated flows that have nowhere to stash a per-browser nonce.
   */
  expectedNonce?: string;
}

export interface VerifyReturnResult {
  target: string;
  data: unknown;
  /** The provider's original `state`, if one was wrapped. */
  providerState?: string;
}

/** True when `value` is a relay token (`<base64url>.<base64url>`). */
export function isRelayState(value: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
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
      ...(input.providerState !== undefined ? { p: input.providerState } : {}),
    };
    const state = await encodeState(key, payload);
    return { state, nonce };
  }

  /**
   * Rewrite a provider authorize URL to route through the broker: its
   * `redirect_uri` becomes the broker URL and its `state` becomes a signed relay
   * token that carries the real target + the provider's original state. Requires
   * `brokerUrl` to have been set on the relay.
   */
  async function wrapAuthorizeUrl(
    authorizeUrl: string,
    data?: unknown,
  ): Promise<WrapAuthorizeUrlResult> {
    if (!options.brokerUrl) {
      throw new Error("wrapAuthorizeUrl requires createRelay({ brokerUrl })");
    }
    const url = new URL(authorizeUrl);
    const target = url.searchParams.get("redirect_uri");
    if (!target) {
      throw new Error("authorize url has no redirect_uri to wrap");
    }
    const providerState = url.searchParams.get("state") ?? undefined;

    const { state, nonce } = await createState({ target, data, providerState });
    url.searchParams.set("redirect_uri", options.brokerUrl);
    url.searchParams.set("state", state);
    return { url: url.toString(), state, nonce };
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
    if (input.expectedNonce !== undefined && payload.n !== input.expectedNonce) {
      throw new RelayError("NonceMismatch", "state nonce did not match stored nonce");
    }
    return { target: payload.t, data: payload.d, providerState: payload.p };
  }

  return {
    createState,
    wrapAuthorizeUrl,
    handleCallback,
    verifyReturn,
    isRelayState,
  };
}

/** The object returned by {@link createRelay}. */
export type Relay = ReturnType<typeof createRelay>;
