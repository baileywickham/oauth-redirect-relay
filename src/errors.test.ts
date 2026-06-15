import { test, expect } from "bun:test";
import { RelayError, type RelayErrorCode } from "./errors";

test("RelayError carries a typed code and is instanceof Error", () => {
  const err = new RelayError("Expired", "state has expired");
  expect(err).toBeInstanceOf(Error);
  expect(err).toBeInstanceOf(RelayError);
  expect(err.code).toBe("Expired");
  expect(err.message).toBe("state has expired");
  expect(err.name).toBe("RelayError");
});

test("error codes are usable as a discriminant", () => {
  const codes: RelayErrorCode[] = [
    "MalformedState",
    "InvalidSignature",
    "Expired",
    "NonceMismatch",
    "TargetNotAllowed",
    "MissingCode",
  ];
  expect(codes.length).toBe(6);
});
