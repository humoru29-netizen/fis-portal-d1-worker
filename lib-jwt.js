/**
 * Minimal HMAC-signed JWT (HS256) using Web Crypto — no npm deps needed.
 * Good enough for internal session tokens between portal.html and the Worker.
 *
 * Token shape: header.payload.signature (all base64url)
 */

const DEFAULT_EXPIRY_SECONDS = 60 * 60 * 12; // 12 hours

function base64urlEncode(bufferOrString) {
  let bytes;
  if (typeof bufferOrString === "string") {
    bytes = new TextEncoder().encode(bufferOrString);
  } else {
    bytes = new Uint8Array(bufferOrString);
  }
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecodeToString(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return atob(padded + pad);
}

async function getKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

/**
 * Sign a payload into a JWT. `payload` should include `sub` (user id)
 * at minimum; `exp` is added automatically if not provided.
 */
export async function signToken(payload, secret, expiresInSeconds = DEFAULT_EXPIRY_SECONDS) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    iat: now,
    exp: now + expiresInSeconds,
    ...payload
  };

  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(fullPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await getKey(secret);
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(signingInput)
  );
  const encodedSignature = base64urlEncode(signatureBuffer);

  return `${signingInput}.${encodedSignature}`;
}

/**
 * Verify a JWT's signature and expiry. Throws if invalid or expired.
 * Returns the decoded payload on success.
 */
export async function verifyToken(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed token.");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const key = await getKey(secret);
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signatureBytes = Uint8Array.from(
    base64urlDecodeToString(encodedSignature),
    c => c.charCodeAt(0)
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    new TextEncoder().encode(signingInput)
  );
  if (!valid) throw new Error("Invalid signature.");

  const payload = JSON.parse(base64urlDecodeToString(encodedPayload));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error("Token expired.");

  return payload;
}
