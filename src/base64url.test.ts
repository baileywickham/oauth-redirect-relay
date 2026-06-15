import { test, expect } from "bun:test";
import { bytesToBase64url, base64urlToBytes } from "./base64url";

test("round-trips arbitrary bytes", () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  const encoded = bytesToBase64url(bytes);
  expect(base64urlToBytes(encoded)).toEqual(bytes);
});

test("produces url-safe output with no padding", () => {
  const encoded = bytesToBase64url(new Uint8Array([0xfb, 0xff, 0xbf]));
  expect(encoded).not.toContain("+");
  expect(encoded).not.toContain("/");
  expect(encoded).not.toContain("=");
});

test("decodes input that lacks padding", () => {
  const encoded = bytesToBase64url(new Uint8Array([1, 2, 3]));
  expect(base64urlToBytes(encoded)).toEqual(new Uint8Array([1, 2, 3]));
});
