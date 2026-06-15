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
