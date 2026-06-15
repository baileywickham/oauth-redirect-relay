import type { Relay } from "./relay";

// Structural subsets of Express's req/res so this adapter needs no express
// dependency. A real Express Request/Response satisfies these.
interface BrokerRequest {
  protocol?: string;
  originalUrl?: string;
  url?: string;
  get(name: string): string | undefined;
}

interface BrokerResponse {
  redirect(location: string): void;
  status(code: number): BrokerResponse;
  send(body: string): void;
}

type NextFn = (err?: unknown) => void;

/**
 * An Express handler for the broker callback. Mount it at the path your OAuth
 * provider's registered redirect URI points to:
 *
 *   app.get("/oauth-relay/callback", expressBroker(relay));
 *
 * It reconstructs the absolute request URL (honoring `x-forwarded-*`), runs
 * `relay.handleCallback`, and either 302s to the verified dev-box target or
 * responds 400 with the error code.
 */
export function expressBroker(relay: Relay) {
  return async (
    req: BrokerRequest,
    res: BrokerResponse,
    next?: NextFn,
  ): Promise<void> => {
    try {
      const proto = req.get("x-forwarded-proto") || req.protocol || "https";
      const host = req.get("x-forwarded-host") || req.get("host");
      const path = req.originalUrl ?? req.url ?? "/";
      const url = `${proto}://${host}${path}`;

      const result = await relay.handleCallback({ url });
      if (result.status === 302) {
        res.redirect(result.location);
        return;
      }
      res.status(result.status).send(`OAuth relay error: ${result.error}`);
    } catch (err) {
      if (next) next(err);
      else throw err;
    }
  };
}
