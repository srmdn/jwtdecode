export interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface ClaimInfo {
  key: string;
  value: unknown;
  label: string;
  description: string;
  formatted: string;
  isTimestamp: boolean;
}

export interface ExpiryStatus {
  state: "expired" | "valid" | "none";
  message: string;
}

export interface DecodedJWT {
  valid: true;
  raw: { header: string; payload: string; signature: string };
  header: JWTHeader;
  payload: JWTPayload;
  hasSignature: boolean;
  expiry: ExpiryStatus;
  headerClaims: ClaimInfo[];
  payloadClaims: ClaimInfo[];
}

export interface FailedJWT {
  valid: false;
  error: string;
}

function b64urlDecode(str: string): string {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + (4 - (b64.length % 4)) % 4, "=");
  return atob(padded);
}

function relativeTime(ts: number): string {
  const diffMs = ts * 1000 - Date.now();
  const abs = Math.abs(diffMs);
  const past = diffMs < 0;

  const s = Math.floor(abs / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  const mo = Math.floor(d / 30);
  const y = Math.floor(d / 365);

  let unit: string;
  if (y > 0) unit = `${y} year${y > 1 ? "s" : ""}`;
  else if (mo > 0) unit = `${mo} month${mo > 1 ? "s" : ""}`;
  else if (d > 0) unit = `${d} day${d > 1 ? "s" : ""}`;
  else if (h > 0) unit = `${h}h ${m % 60}m`;
  else if (m > 0) unit = `${m}m`;
  else unit = `${s}s`;

  return past ? `${unit} ago` : `in ${unit}`;
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

function formatValue(key: string, value: unknown): { text: string; isTimestamp: boolean } {
  if ((key === "exp" || key === "nbf" || key === "iat") && typeof value === "number") {
    return { text: `${formatDate(value)}  ·  ${relativeTime(value)}`, isTimestamp: true };
  }
  if (Array.isArray(value)) return { text: value.join(", "), isTimestamp: false };
  if (typeof value === "object" && value !== null)
    return { text: JSON.stringify(value, null, 2), isTimestamp: false };
  return { text: String(value), isTimestamp: false };
}

const PAYLOAD_CLAIMS: Record<string, { label: string; description: string }> = {
  iss: { label: "Issuer", description: "The principal that issued this token." },
  sub: { label: "Subject", description: "The entity this token is about — usually a user ID." },
  aud: { label: "Audience", description: "The recipients this token is intended for." },
  exp: { label: "Expiration", description: "After this time the token must not be accepted." },
  nbf: { label: "Not Before", description: "Before this time the token must not be accepted." },
  iat: { label: "Issued At", description: "The time at which this token was issued." },
  jti: { label: "JWT ID", description: "A unique identifier for this token. Useful to prevent replay attacks." },
  name: { label: "Name", description: "Full name of the subject." },
  email: { label: "Email", description: "Email address of the subject." },
  email_verified: { label: "Email Verified", description: "Whether the email has been verified." },
  picture: { label: "Picture", description: "URL of the subject's profile picture." },
  role: { label: "Role", description: "Role assigned to the subject." },
  roles: { label: "Roles", description: "Roles assigned to the subject." },
  scope: { label: "Scope", description: "OAuth 2.0 scopes granted to this token." },
  azp: { label: "Authorized Party", description: "The client the token was issued to." },
  at_hash: { label: "Access Token Hash", description: "Hash of the corresponding access token." },
};

const HEADER_CLAIMS: Record<string, { label: string; description: string }> = {
  alg: { label: "Algorithm", description: "Signing algorithm used (e.g. HS256, RS256, ES256)." },
  typ: { label: "Type", description: 'Token type — almost always "JWT".' },
  kid: { label: "Key ID", description: "Identifies which key was used to sign the token." },
  cty: { label: "Content Type", description: "Used when nesting JWTs." },
};

function buildClaims(
  obj: Record<string, unknown>,
  known: Record<string, { label: string; description: string }>
): ClaimInfo[] {
  const knownFirst = Object.keys(known).filter((k) => k in obj);
  const rest = Object.keys(obj).filter((k) => !(k in known));

  return [...knownFirst, ...rest].map((key) => {
    const value = obj[key];
    const meta = known[key];
    const { text, isTimestamp } = formatValue(key, value);
    return {
      key,
      value,
      label: meta?.label ?? key,
      description: meta?.description ?? "",
      formatted: text,
      isTimestamp,
    };
  });
}

function getExpiry(payload: JWTPayload): ExpiryStatus {
  if (typeof payload.exp !== "number") {
    return { state: "none", message: "No expiration set — this token never expires." };
  }
  const now = Date.now() / 1000;
  if (payload.exp < now) {
    return { state: "expired", message: `Expired ${relativeTime(payload.exp)}.` };
  }
  return { state: "valid", message: `Expires ${relativeTime(payload.exp)}.` };
}

export function decodeJWT(token: string): DecodedJWT | FailedJWT {
  const t = token.trim();
  const parts = t.split(".");

  if (parts.length < 2 || parts.length > 3) {
    return { valid: false, error: "A JWT must have 2 or 3 parts separated by dots (header.payload.signature)." };
  }

  let header: JWTHeader;
  let payload: JWTPayload;

  try {
    header = JSON.parse(b64urlDecode(parts[0]));
  } catch {
    return { valid: false, error: "Could not decode the header. Is this a valid JWT?" };
  }

  try {
    payload = JSON.parse(b64urlDecode(parts[1]));
  } catch {
    return { valid: false, error: "Could not decode the payload. Is this a valid JWT?" };
  }

  const signature = parts[2] ?? "";

  return {
    valid: true,
    raw: { header: parts[0], payload: parts[1], signature },
    header,
    payload,
    hasSignature: signature.length > 0,
    expiry: getExpiry(payload),
    headerClaims: buildClaims(header as Record<string, unknown>, HEADER_CLAIMS),
    payloadClaims: buildClaims(payload as Record<string, unknown>, PAYLOAD_CLAIMS),
  };
}
