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
  expect(isTargetAllowed("https://alice.dev.example.com.evil.com/x", opts)).toBe(false);
  expect(isTargetAllowed("http://alice.dev.example.com/x", opts)).toBe(false);
});

test("unparseable url is rejected", () => {
  const opts = { allowLoopback: true, allowedOrigins: [] };
  expect(isTargetAllowed("not a url", opts)).toBe(false);
});
