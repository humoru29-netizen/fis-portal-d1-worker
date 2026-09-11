/**
 * Password hashing using PBKDF2 via Web Crypto — no npm deps needed,
 * works natively in the Cloudflare Workers runtime.
 *
 * Stored format: "pbkdf2$<iterations>$<saltBase64>$<hashBase64>"
 */

const ITERATIONS = 100000;
const HASH_ALGO = "SHA-256";
const KEY_LENGTH = 32; // bytes

function toBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(password, salt, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: HASH_ALGO
    },
    keyMaterial,
    KEY_LENGTH * 8
  );
  return derivedBits;
}

/**
 * Hash a plaintext password. Returns a self-describing string safe to
 * store in the `password_hash` column.
 */
export async function hash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derivedBits = await deriveKey(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(derivedBits)}`;
}

/**
 * Verify a plaintext password against a stored hash string.
 * Uses constant-time comparison to avoid timing attacks.
 */
export async function verify(password, storedHash) {
  const parts = (storedHash || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

  const iterations = parseInt(parts[1], 10);
  const salt = fromBase64(parts[2]);
  const expectedHash = fromBase64(parts[3]);

  const derivedBits = await deriveKey(password, salt, iterations);
  const derivedBytes = new Uint8Array(derivedBits);
  const expectedBytes = new Uint8Array(expectedHash);

  if (derivedBytes.length !== expectedBytes.length) return false;

  // Constant-time comparison
  let diff = 0;
  for (let i = 0; i < derivedBytes.length; i++) {
    diff |= derivedBytes[i] ^ expectedBytes[i];
  }
  return diff === 0;
}
