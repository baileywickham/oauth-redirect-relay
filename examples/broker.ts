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
