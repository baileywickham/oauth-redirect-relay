export type RelayErrorCode =
  | "MalformedState"
  | "InvalidSignature"
  | "Expired"
  | "NonceMismatch"
  | "TargetNotAllowed"
  | "MissingCode";

export class RelayError extends Error {
  readonly code: RelayErrorCode;

  constructor(code: RelayErrorCode, message: string) {
    super(message);
    this.name = "RelayError";
    this.code = code;
  }
}
