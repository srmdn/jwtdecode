import { describe, it, expect } from "bun:test";
import { decodeJWT } from "./decode";

function encodePart(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function tokenFromParts(header: unknown, payload: unknown, signature = "test-signature"): string {
  return `${encodePart(header)}.${encodePart(payload)}${signature ? `.${signature}` : ""}`;
}

const VALID_JWT = tokenFromParts(
  { alg: "HS256", typ: "JWT" },
  { sub: "1234567890", name: "John Doe", iat: 1516239022, exp: 9999999999 },
);

// Expired JWT (exp: 1)
const EXPIRED_JWT = tokenFromParts({ alg: "HS256", typ: "JWT" }, { sub: "user1", exp: 1 });

// JWT without signature (2 parts only)
const NO_SIG_JWT = tokenFromParts({ alg: "HS256", typ: "JWT" }, { sub: "user1", name: "Test" }, "");

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
    const noExp = tokenFromParts({ alg: "none" }, { sub: "user1" });
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
