import { describe, it, expect } from "bun:test";
import { decodeJWT } from "./decode";

// A real HS256 JWT with known payload (non-expired for static claims, exp in far future)
// Header: {"alg":"HS256","typ":"JWT"}
// Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":9999999999}
const VALID_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.Lx6mRFNPZiOzPXXfZ4yFNBbvNk2Gf3r1KbBv2cE8z_g";

// Expired JWT (exp: 1)
const EXPIRED_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6MX0.placeholder";

// JWT without signature (2 parts only)
const NO_SIG_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsIm5hbWUiOiJUZXN0In0";

describe("decodeJWT", () => {
  it("rejects non-JWT input", () => {
    expect(decodeJWT("not.a.jwt.with.too.many.dots").valid).toBe(false);
    expect(decodeJWT("notajwt").valid).toBe(false);
    expect(decodeJWT("").valid).toBe(false);
  });

  it("rejects malformed base64 in header", () => {
    const result = decodeJWT("!!!.payload.sig");
    expect(result.valid).toBe(false);
  });

  it("decodes a valid JWT", () => {
    const result = decodeJWT(VALID_JWT);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.header.alg).toBe("HS256");
    expect(result.header.typ).toBe("JWT");
    expect(result.payload.sub).toBe("1234567890");
    expect(result.payload.name).toBe("John Doe");
    expect(result.hasSignature).toBe(true);
  });

  it("detects a valid (non-expired) token", () => {
    const result = decodeJWT(VALID_JWT);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.expiry.state).toBe("valid");
    expect(result.expiry.message).toContain("Expires");
  });

  it("detects an expired token", () => {
    const result = decodeJWT(EXPIRED_JWT);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.expiry.state).toBe("expired");
    expect(result.expiry.message).toContain("Expired");
  });

  it("handles token without signature (2 parts)", () => {
    const result = decodeJWT(NO_SIG_JWT);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.hasSignature).toBe(false);
    expect(result.raw.signature).toBe("");
  });

  it("handles token with no exp claim", () => {
    // Header: {"alg":"none"} Payload: {"sub":"user1"}
    const noExp = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMSJ9.";
    const result = decodeJWT(noExp);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.expiry.state).toBe("none");
    expect(result.expiry.message).toContain("never expires");
  });

  it("returns headerClaims with known claim labels", () => {
    const result = decodeJWT(VALID_JWT);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    const alg = result.headerClaims.find((c) => c.key === "alg");
    expect(alg?.label).toBe("Algorithm");
    const typ = result.headerClaims.find((c) => c.key === "typ");
    expect(typ?.label).toBe("Type");
  });

  it("returns payloadClaims with known claim labels", () => {
    const result = decodeJWT(VALID_JWT);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    const sub = result.payloadClaims.find((c) => c.key === "sub");
    expect(sub?.label).toBe("Subject");
    const iat = result.payloadClaims.find((c) => c.key === "iat");
    expect(iat?.label).toBe("Issued At");
    expect(iat?.isTimestamp).toBe(true);
  });

  it("trims whitespace from token input", () => {
    const result = decodeJWT(`  ${VALID_JWT}  `);
    expect(result.valid).toBe(true);
  });
});
