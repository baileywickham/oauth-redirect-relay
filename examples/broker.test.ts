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
