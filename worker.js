// @ts-nocheck

/**
 * FIS Itobe Portal — Cloudflare D1 Worker (single-file build)
 * Combines auth, student login, attendance, and assignments into one file
 * to work around the mobile editor's limited multi-file support.
 *
 * Bindings expected (Settings -> Bindings):
 *   DB         -> D1 database binding, pointed at fis-portal-db
 *   JWT_SECRET -> Secret, any long random string
 */

// =====================================================================
// SECTION 1: Password hashing (PBKDF2 via Web Crypto)
// =====================================================================
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
async function hash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derivedBits = await deriveKey(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(derivedBits)}`;
}

/**
 * Verify a plaintext password against a stored hash string.
 * Uses constant-time comparison to avoid timing attacks.
 */
async function verify(password, storedHash) {
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

// =====================================================================
// SECTION 1B: Reversible PIN encryption (AES-GCM via Web Crypto)
// =====================================================================
/**
 * Student login PINs are stored one-way hashed (above) for verifying a
 * login attempt, but that means a PIN can never be shown again once
 * generated. To let an admin reprint an already-issued PIN without
 * changing it, we also keep a reversible, encrypted copy, keyed from
 * JWT_SECRET so no extra binding is needed.
 * Stored format: "<ivBase64>.<ciphertextBase64>"
 */
async function getPinEncKey(env) {
  const raw = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(env.JWT_SECRET + ":pin-enc")
  );
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptPin(pin, env) {
  const key = await getPinEncKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(pin)
  );
  return `${toBase64(iv)}.${toBase64(ciphertext)}`;
}

async function decryptPin(encrypted, env) {
  if (!encrypted) return null;
  const [ivB64, ctB64] = encrypted.split(".");
  if (!ivB64 || !ctB64) return null;
  try {
    const key = await getPinEncKey(env);
    const iv = new Uint8Array(fromBase64(ivB64));
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, fromBase64(ctB64));
    return new TextDecoder().decode(plainBuf);
  } catch {
    // Covers PINs generated before this feature existed (no pin_enc yet)
    // or any decrypt failure — caller treats a null return as unrecoverable.
    return null;
  }
}

// =====================================================================
// SECTION 2: JWT (HMAC-signed session tokens via Web Crypto)
// =====================================================================
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
async function signToken(payload, secret, expiresInSeconds = DEFAULT_EXPIRY_SECONDS) {
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
async function verifyToken(token, secret) {
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

// =====================================================================
// SECTION 3: Shared session helper (staff + student)
// =====================================================================
/**
 * Shared session helper — used by every Worker route file.
 * Two kinds of session token, distinguished by payload.type:
 *   'staff'   -> sub = users.id      (password login)
 *   'student' -> sub = students.id   (admission no + PIN login)
 */


async function getSession(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) return null;

  let payload;
  try {
    payload = await verifyToken(token, env.JWT_SECRET);
  } catch {
    return null;
  }

  if (payload.type === "staff") {
    const user = await env.DB
      .prepare("SELECT * FROM users WHERE id = ? AND status = 'active'")
      .bind(payload.sub)
      .first();
    if (!user) return null;
    return { type: "staff", id: user.id, role: user.role, level: user.level, record: user };
  }

  if (payload.type === "student") {
    const student = await env.DB
      .prepare("SELECT * FROM students WHERE id = ? AND status = 'active'")
      .bind(payload.sub)
      .first();
    if (!student) return null;
    return { type: "student", id: student.id, record: student };
  }

  return null;
}

function isStaff(session) {
  return !!session && session.type === "staff";
}

function isAdminSession(session) {
  return isStaff(session) && ["general_admin", "primary_admin", "secondary_admin"].includes(session.role);
}

function isGeneralAdmin(session) {
  return isStaff(session) && session.role === "general_admin";
}

function isTeachingStaff(session) {
  return isStaff(session) && ["general_admin", "primary_admin", "secondary_admin", "teacher"].includes(session.role);
}

function isOwnStudent(session, studentId) {
  return !!session && session.type === "student" && session.id === studentId;
}

/**
 * Returns 'primary' or 'secondary' if this session belongs to a level-scoped
 * admin (primary_admin / secondary_admin), or null if unrestricted
 * (general_admin, or not an admin at all). Every route that touches a
 * specific class, student, staff member, or level-tagged record should
 * check this and reject/filter anything outside the admin's own level.
 */
function adminLevelRestriction(session) {
  if (!isStaff(session)) return null;
  if (session.role === "primary_admin") return "primary";
  if (session.role === "secondary_admin") return "secondary";
  return null;
}

// =====================================================================
// SECTION 4: Auth & account approval routes
// =====================================================================

// =====================================================================
// SECTION 5: Student login routes (admission no + PIN)
// =====================================================================

// =====================================================================
// SECTION 6: Attendance routes
// =====================================================================

// =====================================================================
// SECTION 7: Assignment routes
// =====================================================================
/**
 * FIS Itobe Portal — Worker route module (Auth & Account Approval)
 * Exported as a route handler, combined with other modules in index.js.
 *
 * Routes:
 *   POST /api/signup            { name, email, password, requestedRole, requestedLevel }
 *   POST /api/login             { email, password }
 *   GET  /api/approvals         (auth: general_admin) list pending users
 *   POST /api/approvals/:id     (auth: general_admin) { action: 'approve'|'reject', role, level }
 *   GET  /api/me                (auth: any staff) return current user profile
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// =====================================================================
// AI class-list reader (handwriting-capable). Needs secret ANTHROPIC_API_KEY.
// =====================================================================
async function scanRosterImage(request, env) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: "AI reader not set up yet." }, 501);

  let body;
  try { body = await request.json(); } catch { return json({ error: "Bad request." }, 400); }
  const image = body && body.image;
  if (!image || image.length > 7000000) return json({ error: "Photo missing or too large." }, 400);

  let res;
  try {
    res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 1500,
        messages: [{
          role: "user",
          content: [
            { type: "image", source: { type: "base64", media_type: body.mediaType || "image/jpeg", data: image } },
            { type: "text", text:
              "This is a photo of a school class list (possibly handwritten). " +
              "Extract ONLY the student names, in the order written, one per entry. " +
              "Ignore the title, dates, row numbers, headers, scores, and any admission or other numbers. " +
              "Keep the full name as written (surname and other names together). " +
              "If a name is unclear, give your best reading. " +
              "Reply with ONLY a JSON array of strings, e.g. [\"Ahmed Abdulrahman\",\"Precious Okafor\"]. " +
              "If there are no names, reply []." }
          ]
        }]
      })
    });
  } catch {
    return json({ error: "AI reader could not be reached. Try again or type the names." }, 502);
  }
  if (!res.ok) return json({ error: "AI reader is unavailable right now. Try again or type the names." }, 502);

  const data = await res.json();
  const text = (data.content || []).map(c => c.text || "").join("").replace(/```json|```/g, "").trim();
  let names = [];
  try { names = JSON.parse(text); } catch { names = []; }
  if (!Array.isArray(names)) names = [];
  names = names.map(n => String(n).trim()).filter(n => n.length > 1).slice(0, 200);
  return json({ names });
}

function uuid() {
  return crypto.randomUUID();
}

/**
 * Returns a Response if this module handles the request, or null to let
 * the router try the next module.
 */
async function handleAuthRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- SIGNUP ----------------
  if (pathname === "/api/signup" && request.method === "POST") {
    const { name, email, password, requestedRole, requestedLevel } = await request.json();

    if (!name || !email || !password) {
      return json({ error: "Missing required fields." }, 400);
    }
    if (password.length < 8) {
      return json({ error: "Password must be at least 8 characters." }, 400);
    }

    const existing = await env.DB
      .prepare("SELECT id FROM users WHERE email = ?")
      .bind(email.toLowerCase())
      .first();
    if (existing) {
      return json({ error: "That email is already registered." }, 409);
    }

    const passwordHash = await hash(password);
    const id = uuid();

    await env.DB
      .prepare(
        `INSERT INTO users (id, name, email, password_hash, role, status, requested_role, requested_level, self_registered)
         VALUES (?, ?, ?, ?, 'pending', 'pending', ?, ?, 1)`
      )
      .bind(id, name, email.toLowerCase(), passwordHash, requestedRole, requestedLevel)
      .run();

    return json({
      message: "Account request submitted. An administrator must approve it before you can sign in."
    });
  }

  // ---------------- LOGIN ----------------
  if (pathname === "/api/login" && request.method === "POST") {
    const { email, password } = await request.json();
    const user = await env.DB
      .prepare("SELECT * FROM users WHERE email = ?")
      .bind((email || "").toLowerCase())
      .first();

    if (!user) return json({ error: "Invalid email or password." }, 401);

    const valid = await verify(password, user.password_hash);
    if (!valid) return json({ error: "Invalid email or password." }, 401);

    if (user.status === "pending") {
      return json({ error: "Your account is awaiting administrator approval." }, 403);
    }
    if (user.status === "rejected") {
      return json({ error: "This account request was not approved. Please contact the school administrator." }, 403);
    }
    if (user.status === "suspended") {
      return json({ error: "This account has been suspended. Please contact the school administrator." }, 403);
    }

    const token = await signToken({ sub: user.id, type: "staff", role: user.role }, env.JWT_SECRET);
    return json({
      token,
      user: { id: user.id, name: user.name, role: user.role, level: user.level }
    });
  }

  // ---------------- REFRESH TOKEN ----------------
  // Called silently by the frontend while a session is still active, to
  // extend it before it expires (staff: 12h, student: 6h) without forcing
  // a fresh login. Requires a still-valid token — an already-expired token
  // fails getSession() and gets 401 like any other protected route.
  if (pathname === "/api/refresh" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx) return json({ error: "Not authenticated." }, 401);

    const payload = sessionCtx.type === "staff"
      ? { sub: sessionCtx.id, type: "staff", role: sessionCtx.role }
      : { sub: sessionCtx.id, type: "student" };
    const expiresInSeconds = sessionCtx.type === "student" ? 60 * 60 * 6 : DEFAULT_EXPIRY_SECONDS;

    const token = await signToken(payload, env.JWT_SECRET, expiresInSeconds);
    return json({ token });
  }

  // ---------------- ME ----------------
  if (pathname === "/api/me" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx || sessionCtx.type !== "staff") return json({ error: "Not authenticated." }, 401);
    const u = sessionCtx.record;
    return json({ id: u.id, name: u.name, email: u.email, role: u.role, level: u.level });
  }

  // ---------------- LIST PENDING APPROVALS ----------------
  if (pathname === "/api/approvals" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const level = url.searchParams.get("level");
    const stmt = level
      ? env.DB.prepare("SELECT id, name, email, requested_role, requested_level, created_at FROM users WHERE status = 'pending' AND requested_level = ?").bind(level)
      : env.DB.prepare("SELECT id, name, email, requested_role, requested_level, created_at FROM users WHERE status = 'pending'");

    const { results } = await stmt.all();
    return json({ requests: results });
  }

  // ---------------- APPROVE / REJECT ----------------
  const approvalMatch = pathname.match(/^\/api\/approvals\/([^/]+)$/);
  if (approvalMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const userId = approvalMatch[1];
    const { action, role, level } = await request.json();

    const target = await env.DB
      .prepare("SELECT * FROM users WHERE id = ? AND status = 'pending'")
      .bind(userId)
      .first();
    if (!target) return json({ error: "Request not found or already handled." }, 404);

    if (action === "approve") {
      if (!role) return json({ error: "Approved role is required." }, 400);
      await env.DB
        .prepare(
          `UPDATE users SET status = 'active', role = ?, level = ?, approved_by = ?, approved_at = datetime('now')
           WHERE id = ?`
        )
        .bind(role, level || target.requested_level, sessionCtx.id, userId)
        .run();
      return json({ message: "Account approved." });
    }

    if (action === "reject") {
      await env.DB
        .prepare(
          `UPDATE users SET status = 'rejected', approved_by = ?, approved_at = datetime('now') WHERE id = ?`
        )
        .bind(sessionCtx.id, userId)
        .run();
      return json({ message: "Account rejected." });
    }

    return json({ error: "Invalid action." }, 400);
  }

  return null; // not handled here — let the router try the next module
}
/**
 * FIS Itobe Portal — Worker API (Student Login)
 * Students authenticate with Admission Number + PIN (no email/password account),
 * matching the existing Firebase-era model. On success, issues a JWT scoped to
 * that student only (type: 'student'), usable against student-facing endpoints
 * like /api/attendance/student/:studentId, /api/assignments, /api/notes.
 *
 * Routes:
 *   POST /api/student-login   { admissionNo, pin, term, session }
 *   GET  /api/student-me      (auth: student) return own profile
 *
 * PIN lockout: after PIN_LOCK_THRESHOLD wrong PINs in a row for a given
 * term/session, that PIN is locked for PIN_LOCK_MINUTES. A fresh PIN
 * (regenerated by an admin) always clears the lockout immediately.
 */
const PIN_LOCK_THRESHOLD = 5;
const PIN_LOCK_MINUTES = 15;




async function handleStudentAuthRoutes(request, env, url) {
    const { pathname } = url;

    // ---------------- STUDENT LOGIN ----------------
    if (pathname === "/api/student-login" && request.method === "POST") {
      const { admissionNo, pin, term, session } = await request.json();
      if (!admissionNo || !pin || !term || !session) {
        return json({ error: "Admission number, PIN, term, and session are required." }, 400);
      }

      const student = await env.DB
        .prepare("SELECT * FROM students WHERE admission_no = ? AND status = 'active'")
        .bind(admissionNo.trim())
        .first();
      if (!student) {
        return json({ error: "Admission number not found." }, 404);
      }

      const pinRow = await env.DB
        .prepare(
          `SELECT * FROM student_pins WHERE student_id = ? AND term = ? AND session = ?`
        )
        .bind(student.id, term, session)
        .first();
      if (!pinRow) {
        return json({ error: "No PIN has been generated for this term/session yet." }, 404);
      }

      // Lockout guard: too many wrong PINs in a row locks this term/session's
      // PIN for a cooldown period, regardless of whether this attempt is correct.
      if (pinRow.locked_until) {
        const lockedUntilMs = new Date(pinRow.locked_until + "Z").getTime();
        if (lockedUntilMs > Date.now()) {
          const minutesLeft = Math.max(1, Math.ceil((lockedUntilMs - Date.now()) / 60000));
          return json({
            error: `Too many incorrect attempts. Try again in ${minutesLeft} minute(s), or ask an admin to reset your PIN.`
          }, 423);
        }
      }

      const valid = await verify(pin, pinRow.pin_hash);
      if (!valid) {
        const attempts = (pinRow.failed_attempts || 0) + 1;
        const remaining = PIN_LOCK_THRESHOLD - attempts;

        if (remaining <= 0) {
          await env.DB
            .prepare(
              `UPDATE student_pins SET failed_attempts = ?, locked_until = datetime('now', '+' || ? || ' minutes')
               WHERE id = ?`
            )
            .bind(attempts, PIN_LOCK_MINUTES, pinRow.id)
            .run();
          return json({
            error: `Too many incorrect attempts. This PIN is locked for ${PIN_LOCK_MINUTES} minutes. Ask an admin to reset your PIN if you need in sooner.`
          }, 423);
        }

        await env.DB
          .prepare(`UPDATE student_pins SET failed_attempts = ? WHERE id = ?`)
          .bind(attempts, pinRow.id)
          .run();
        return json({ error: `Incorrect PIN. ${remaining} attempt(s) remaining before a temporary lockout.` }, 401);
      }

      // Correct PIN — clear any accumulated failed attempts.
      if (pinRow.failed_attempts || pinRow.locked_until) {
        await env.DB
          .prepare(`UPDATE student_pins SET failed_attempts = 0, locked_until = NULL WHERE id = ?`)
          .bind(pinRow.id)
          .run();
      }

      const token = await signToken(
        { sub: student.id, type: "student" },
        env.JWT_SECRET,
        60 * 60 * 6 // 6-hour session — shorter-lived than staff, re-enter PIN next visit
      );

      return json({
        token,
        student: {
          id: student.id,
          name: student.name,
          admissionNo: student.admission_no,
          classId: student.class_id,
          level: student.level,
          photoUrl: student.photo_key || null
        }
      });
    }

    // ---------------- STUDENT SELF PROFILE ----------------
    if (pathname === "/api/student-me" && request.method === "GET") {
      const sessionCtx = await getSession(request, env);
      if (!sessionCtx || sessionCtx.type !== "student") {
        return json({ error: "Not authenticated." }, 401);
      }
      const s = sessionCtx.record;
      return json({
        id: s.id, name: s.name, admissionNo: s.admission_no,
        classId: s.class_id, level: s.level, photoUrl: s.photo_key || null
      });
    }

    return null; // not handled here — let the router try the next module
}
/**
 * FIS Itobe Portal — Worker API (Attendance)
 * Bindings expected:
 *   DB -> D1 database binding (fis-portal-db)
 *
 * Routes:
 *   POST /api/attendance              (auth: teacher/admin) mark attendance for a class/date
 *        body: { classId, date, term, session, records: [{ studentId, status }] }
 *   GET  /api/attendance?classId=&date=          (auth: teacher/admin) view one day for a class
 *   GET  /api/attendance/student/:studentId?term=&session=   (auth: any logged-in; student sees own)
 *   GET  /api/attendance/summary?classId=&term=&session=     (auth: teacher/admin) per-student totals
 */






const VALID_STATUSES = ["present", "absent", "late", "excused"];

async function handleAttendanceRoutes(request, env, url) {
    const { pathname } = url;

    // ---------------- MARK ATTENDANCE (bulk, one class/date) ----------------
    if (pathname === "/api/attendance" && request.method === "POST") {
      const sessionCtx = await getSession(request, env);
      if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

      const { classId, date, term, session, records } = await request.json();
      if (!classId || !date || !term || !session || !Array.isArray(records) || !records.length) {
        return json({ error: "classId, date, term, session, and records[] are required." }, 400);
      }
      for (const r of records) {
        if (!r.studentId || !VALID_STATUSES.includes(r.status)) {
          return json({ error: `Invalid record: ${JSON.stringify(r)}` }, 400);
        }
      }

      const restriction = adminLevelRestriction(sessionCtx);
      if (restriction) {
        const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
        if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
      }

      // Verify the class itself still exists (catches a stale/removed class id
      // reaching here from a cached dropdown).
      const classRow = await env.DB.prepare("SELECT id FROM classes WHERE id = ?").bind(classId).first();
      if (!classRow) {
        return json({ error: "This class could not be found. Please refresh the page and try again." }, 404);
      }

      // Verify every submitted student actually belongs to this class right
      // now. This is the #1 real-world cause of a FOREIGN KEY error here: the
      // page loaded a roster, then before saving, one of those students was
      // moved to a different class, deactivated, or deleted — so their id no
      // longer matches (class_id, id) together, even though the id itself
      // still exists somewhere. Catching it here gives a precise, actionable
      // error instead of a generic database failure.
      const studentIds = records.map(r => r.studentId);
      const placeholders = studentIds.map(() => "?").join(",");
      const { results: matchedStudents } = await env.DB
        .prepare(`SELECT id, name FROM students WHERE class_id = ? AND id IN (${placeholders})`)
        .bind(classId, ...studentIds)
        .all();
      const matchedIds = new Set(matchedStudents.map(s => s.id));
      const badIds = studentIds.filter(id => !matchedIds.has(id));

      if (badIds.length) {
        return json({
          error: `${badIds.length} student record(s) could not be saved — they may have been moved to a different class or removed. Please refresh the class roster and try again.`,
          invalidStudentIds: badIds
        }, 409);
      }

      // Upsert each record — one row per student per date (see UNIQUE constraint).
      // Inserted sequentially rather than via env.DB.batch(): D1's batch() has
      // been observed to throw a FOREIGN KEY constraint error even when every
      // row is individually valid (confirmed here — the same statement run
      // one at a time via the D1 console succeeded with the exact same ids
      // that failed inside a batch()). Sequential .run() calls avoid that.
      let savedCount = 0;
      for (const r of records) {
        try {
          await env.DB
            .prepare(
              `INSERT INTO attendance (id, student_id, class_id, date, status, term, session, marked_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(student_id, date) DO UPDATE SET
                 status = excluded.status,
                 marked_by = excluded.marked_by,
                 marked_at = datetime('now')`
            )
            .bind(uuid(), r.studentId, classId, date, r.status, term, session, sessionCtx.id)
            .run();
          savedCount++;
        } catch (rowErr) {
          const studentName = (matchedStudents.find(s => s.id === r.studentId) || {}).name || r.studentId;
          return json({
            error: `Could not save attendance for ${studentName}: ${rowErr.message || rowErr}. ${savedCount} record(s) before this one were saved successfully.`
          }, 500);
        }
      }

      return json({ message: `Attendance saved for ${records.length} student(s).` });
    }

    // ---------------- VIEW ONE DAY FOR A CLASS ----------------
    if (pathname === "/api/attendance" && request.method === "GET") {
      const sessionCtx = await getSession(request, env);
      if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

      const classId = url.searchParams.get("classId");
      const date = url.searchParams.get("date");
      if (!classId || !date) return json({ error: "classId and date are required." }, 400);

      const restriction = adminLevelRestriction(sessionCtx);
      if (restriction) {
        const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
        if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
      }

      const { results } = await env.DB
        .prepare(
          `SELECT s.id AS student_id, s.name AS student_name, a.status
           FROM students s
           LEFT JOIN attendance a ON a.student_id = s.id AND a.date = ?
           WHERE s.class_id = ? AND s.status = 'active'
           ORDER BY s.name COLLATE NOCASE`
        )
        .bind(date, classId)
        .all();

      return json({ classId, date, students: results });
    }

    // ---------------- STUDENT'S OWN HISTORY ----------------
    const studentMatch = pathname.match(/^\/api\/attendance\/student\/([^/]+)$/);
    if (studentMatch && request.method === "GET") {
      const sessionCtx = await getSession(request, env);
      if (!sessionCtx) return json({ error: "Not authenticated." }, 401);

      const studentId = studentMatch[1];
      // Staff can view any student; a student session can only view its own record.
      if (!isTeachingStaff(sessionCtx) && !isOwnStudent(sessionCtx, studentId)) {
        return json({ error: "Not authorised." }, 403);
      }

      const restriction = adminLevelRestriction(sessionCtx);
      if (restriction) {
        const stu = await env.DB.prepare("SELECT level FROM students WHERE id = ?").bind(studentId).first();
        if (!stu || stu.level !== restriction) return json({ error: "Not authorised for this student." }, 403);
      }

      const term = url.searchParams.get("term");
      const session = url.searchParams.get("session");
      if (!term || !session) return json({ error: "term and session are required." }, 400);

      const { results } = await env.DB
        .prepare(
          `SELECT date, status FROM attendance
           WHERE student_id = ? AND term = ? AND session = ?
           ORDER BY date`
        )
        .bind(studentId, term, session)
        .all();

      const totals = results.reduce((acc, r) => {
        acc[r.status] = (acc[r.status] || 0) + 1;
        return acc;
      }, {});

      return json({ studentId, term, session, days: results, totals });
    }

    // ---------------- CLASS SUMMARY (per-student totals for a term) ----------------
    if (pathname === "/api/attendance/summary" && request.method === "GET") {
      const sessionCtx = await getSession(request, env);
      if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

      const classId = url.searchParams.get("classId");
      const term = url.searchParams.get("term");
      const session = url.searchParams.get("session");
      if (!classId || !term || !session) {
        return json({ error: "classId, term, and session are required." }, 400);
      }

      const restriction = adminLevelRestriction(sessionCtx);
      if (restriction) {
        const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
        if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
      }

      const { results } = await env.DB
        .prepare(
          `SELECT s.id AS student_id, s.name,
                  SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS present_count,
                  SUM(CASE WHEN a.status = 'absent'  THEN 1 ELSE 0 END) AS absent_count,
                  SUM(CASE WHEN a.status = 'late'    THEN 1 ELSE 0 END) AS late_count,
                  SUM(CASE WHEN a.status = 'excused' THEN 1 ELSE 0 END) AS excused_count,
                  COUNT(a.id) AS total_marked
           FROM students s
           LEFT JOIN attendance a ON a.student_id = s.id AND a.term = ? AND a.session = ?
           WHERE s.class_id = ? AND s.status = 'active'
           GROUP BY s.id, s.name
           ORDER BY s.name COLLATE NOCASE`
        )
        .bind(term, session, classId)
        .all();

      return json({ classId, term, session, summary: results });
    }

    return null; // not handled here — let the router try the next module
}

/**
 * FIS Itobe Portal — Worker route module (Timetable)
 *
 * Routes:
 *   GET    /api/timetable?classId=                (auth: any logged-in) full week for a class
 *   GET    /api/timetable/teacher/:teacherId       (auth: any logged-in) a teacher's own week, across classes
 *   POST   /api/timetable                          (auth: admin, or teacher for their own slot) create/update a slot
 *          body: { classId, subjectId, teacherId, dayOfWeek, startTime, endTime }
 *   DELETE /api/timetable/:id                      (auth: admin, or teacher who owns the slot)
 *
 * Permission rule: admins (general/primary/secondary, subject to level
 * restriction) can create/edit/delete any slot. A teacher may only
 * create/edit/delete a slot where teacherId equals their own session id —
 * enforced server-side here, not just hidden in the UI.
 */

const VALID_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"];

async function handleTimetableRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- VIEW FULL WEEK FOR A CLASS ----------------
  if (pathname === "/api/timetable" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx) return json({ error: "Not authenticated." }, 401);

    let classId = url.searchParams.get("classId");
    // A student can only ever see their own class's timetable, whatever classId is sent.
    if (sessionCtx.type === "student") {
      classId = sessionCtx.record.class_id;
      if (!classId) return json({ error: "You have not been placed in a class yet." }, 404);
    }
    if (!classId) return json({ error: "classId is required." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT t.id, t.day_of_week, t.start_time, t.end_time,
                t.subject_id, sub.name AS subject_name,
                t.teacher_id, u.name AS teacher_name
         FROM timetable_slots t
         JOIN subjects sub ON sub.id = t.subject_id
         LEFT JOIN users u ON u.id = t.teacher_id
         WHERE t.class_id = ?
         ORDER BY t.day_of_week, t.start_time`
      )
      .bind(classId)
      .all();

    return json({ classId, slots: results });
  }

  // ---------------- A TEACHER'S OWN WEEK, ACROSS CLASSES ----------------
  const teacherMatch = pathname.match(/^\/api\/timetable\/teacher\/([^/]+)$/);
  if (teacherMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx) return json({ error: "Not authenticated." }, 401);

    const teacherId = teacherMatch[1];
    // A teacher may only view their own schedule this way; admins may view anyone's.
    if (!isAdminSession(sessionCtx) && sessionCtx.id !== teacherId) {
      return json({ error: "Not authorised." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT t.id, t.day_of_week, t.start_time, t.end_time,
                t.class_id, c.name AS class_name,
                t.subject_id, sub.name AS subject_name
         FROM timetable_slots t
         JOIN classes c ON c.id = t.class_id
         JOIN subjects sub ON sub.id = t.subject_id
         WHERE t.teacher_id = ?
         ORDER BY t.day_of_week, t.start_time`
      )
      .bind(teacherId)
      .all();

    return json({ teacherId, slots: results });
  }

  // ---------------- CREATE / UPDATE A SLOT ----------------
  if (pathname === "/api/timetable" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { classId, subjectId, teacherId, dayOfWeek, startTime, endTime } = await request.json();
    if (!classId || !subjectId || !dayOfWeek || !startTime || !endTime) {
      return json({ error: "classId, subjectId, dayOfWeek, startTime, and endTime are required." }, 400);
    }
    if (!VALID_DAYS.includes(dayOfWeek)) {
      return json({ error: `dayOfWeek must be one of: ${VALID_DAYS.join(", ")}` }, 400);
    }

    // Teachers (non-admin) may only manage their own slots.
    if (!isAdminSession(sessionCtx)) {
      if (!teacherId || teacherId !== sessionCtx.id) {
        return json({ error: "Teachers may only assign themselves to a slot." }, 403);
      }
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    await env.DB.prepare(
      `INSERT INTO timetable_slots (id, class_id, subject_id, teacher_id, day_of_week, start_time, end_time)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(class_id, day_of_week, start_time) DO UPDATE SET
         subject_id = excluded.subject_id,
         teacher_id = excluded.teacher_id,
         end_time = excluded.end_time`
    ).bind(uuid(), classId, subjectId, teacherId || null, dayOfWeek, startTime, endTime).run();

    return json({ message: "Timetable slot saved." });
  }

  // ---------------- DELETE A SLOT ----------------
  const deleteMatch = pathname.match(/^\/api\/timetable\/([^/]+)$/);
  if (deleteMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const slotId = deleteMatch[1];
    const slot = await env.DB.prepare("SELECT class_id, teacher_id FROM timetable_slots WHERE id = ?").bind(slotId).first();
    if (!slot) return json({ error: "Slot not found." }, 404);

    if (!isAdminSession(sessionCtx) && slot.teacher_id !== sessionCtx.id) {
      return json({ error: "You may only delete your own slots." }, 403);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(slot.class_id).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    await env.DB.prepare("DELETE FROM timetable_slots WHERE id = ?").bind(slotId).run();
    return json({ message: "Timetable slot deleted." });
  }

  return null; // not handled here — let the router try the next module
}

/**
 * FIS Itobe Portal — Worker route module (Assignments)
 *
 * Routes:
 *   POST /api/assignments                         (auth: teaching staff) create an assignment
 *        body: { title, description, classId, subjectId, dueDate, term, session }
 *   GET  /api/assignments?classId=&term=&session=  (auth: staff, or student — student sees own class only)
 *   GET  /api/assignments/:id                      (auth: any logged-in)
 *   POST /api/assignments/:id/submit               (auth: student) mark own submission as submitted
 *   GET  /api/assignments/:id/submissions          (auth: teaching staff) per-student submission status
 *   PATCH /api/assignments/:id/submissions/:studentId  (auth: teaching staff) set remark/grade status
 *   DELETE /api/assignments/:id                    (auth: teaching staff) delete an assignment
 *        and its submissions
 */






const SUBMISSION_STATUSES = ["not_submitted", "submitted", "late", "graded"];

async function handleAssignmentRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- CREATE ASSIGNMENT ----------------
  if (pathname === "/api/assignments" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { title, description, classId, subjectId, dueDate, term, session } = await request.json();
    if (!title || !classId || !subjectId || !dueDate || !term || !session) {
      return json({ error: "title, classId, subjectId, dueDate, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO assignments (id, title, description, class_id, subject_id, due_date, term, session, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(id, title, description || "", classId, subjectId, dueDate, term, session, sessionCtx.id)
      .run();

    return json({ id, message: "Assignment created." });
  }

  // ---------------- LIST ASSIGNMENTS FOR A CLASS ----------------
  if (pathname === "/api/assignments" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx) return json({ error: "Not authenticated." }, 401);

    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    let classId = url.searchParams.get("classId");

    if (!term || !session) return json({ error: "term and session are required." }, 400);

    if (sessionCtx.type === "student") {
      // Students can only ever see their own class's assignments,
      // regardless of what classId (if any) they pass.
      classId = sessionCtx.record.class_id;
    } else if (!classId) {
      return json({ error: "classId is required for staff requests." }, 400);
    }

    if (sessionCtx.type === "student") {
      if (!classId) return json({ error: "You have not been placed in a class yet." }, 404);
      // Student view: include subject name plus this student's OWN submission status/remark only.
      const { results } = await env.DB
        .prepare(
          `SELECT a.id, a.title, a.description, a.due_date, a.subject_id, a.term, a.session, a.created_at,
                  sub.name AS subject_name,
                  s.status AS submission_status, s.submitted_at, s.remark
           FROM assignments a
           LEFT JOIN subjects sub ON sub.id = a.subject_id
           LEFT JOIN assignment_submissions s ON s.assignment_id = a.id AND s.student_id = ?
           WHERE a.class_id = ? AND a.term = ? AND a.session = ?
           ORDER BY a.due_date`
        )
        .bind(sessionCtx.id, classId, term, session)
        .all();
      return json({ classId, term, session, assignments: results });
    }

    const { results } = await env.DB
      .prepare(
        `SELECT id, title, description, due_date, subject_id, term, session, created_at
         FROM assignments
         WHERE class_id = ? AND term = ? AND session = ?
         ORDER BY due_date`
      )
      .bind(classId, term, session)
      .all();

    return json({ classId, term, session, assignments: results });
  }

  // ---------------- ASSIGNMENT DETAIL ----------------
  const detailMatch = pathname.match(/^\/api\/assignments\/([^/]+)$/);
  if (detailMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx) return json({ error: "Not authenticated." }, 401);

    const assignment = await env.DB
      .prepare("SELECT * FROM assignments WHERE id = ?")
      .bind(detailMatch[1])
      .first();
    if (!assignment) return json({ error: "Assignment not found." }, 404);

    if (sessionCtx.type === "student" && sessionCtx.record.class_id !== assignment.class_id) {
      return json({ error: "Not authorised." }, 403);
    }

    return json({ assignment });
  }

  // ---------------- STUDENT SUBMITS ----------------
  const submitMatch = pathname.match(/^\/api\/assignments\/([^/]+)\/submit$/);
  if (submitMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx || sessionCtx.type !== "student") {
      return json({ error: "Only students can submit assignments." }, 403);
    }

    const assignmentId = submitMatch[1];
    const assignment = await env.DB
      .prepare("SELECT * FROM assignments WHERE id = ?")
      .bind(assignmentId)
      .first();
    if (!assignment) return json({ error: "Assignment not found." }, 404);
    if (assignment.class_id !== sessionCtx.record.class_id) {
      return json({ error: "This assignment is not for your class." }, 403);
    }

    const now = new Date();
    // A date-only due date (YYYY-MM-DD) means the END of that day (Nigeria time, UTC+1),
    // so submitting on the due date itself is never counted late.
    const dueRaw = String(assignment.due_date || "");
    const due = /^\d{4}-\d{2}-\d{2}$/.test(dueRaw)
      ? new Date(dueRaw + "T23:59:59+01:00")
      : new Date(dueRaw);
    const status = now > due ? "late" : "submitted";

    const existing = await env.DB
      .prepare("SELECT id FROM assignment_submissions WHERE assignment_id = ? AND student_id = ?")
      .bind(assignmentId, sessionCtx.id)
      .first();

    if (existing) {
      await env.DB
        .prepare(
          `UPDATE assignment_submissions SET status = ?, submitted_at = datetime('now')
           WHERE assignment_id = ? AND student_id = ?`
        )
        .bind(status, assignmentId, sessionCtx.id)
        .run();
    } else {
      await env.DB
        .prepare(
          `INSERT INTO assignment_submissions (id, assignment_id, student_id, status, submitted_at)
           VALUES (?, ?, ?, ?, datetime('now'))`
        )
        .bind(uuid(), assignmentId, sessionCtx.id, status)
        .run();
    }

    return json({ message: status === "late" ? "Submitted late." : "Submitted." , status });
  }

  // ---------------- TEACHER VIEWS SUBMISSIONS FOR AN ASSIGNMENT ----------------
  const submissionsMatch = pathname.match(/^\/api\/assignments\/([^/]+)\/submissions$/);
  if (submissionsMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const assignmentId = submissionsMatch[1];
    const assignment = await env.DB
      .prepare("SELECT * FROM assignments WHERE id = ?")
      .bind(assignmentId)
      .first();
    if (!assignment) return json({ error: "Assignment not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(assignment.class_id).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this assignment." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT s.id AS student_id, s.name,
                COALESCE(sub.status, 'not_submitted') AS status,
                sub.submitted_at, sub.remark
         FROM students s
         LEFT JOIN assignment_submissions sub
           ON sub.student_id = s.id AND sub.assignment_id = ?
         WHERE s.class_id = ? AND s.status = 'active'
         ORDER BY s.name COLLATE NOCASE`
      )
      .bind(assignmentId, assignment.class_id)
      .all();

    return json({ assignmentId, submissions: results });
  }

  // ---------------- TEACHER GRADES/REMARKS A SUBMISSION ----------------
  const gradeMatch = pathname.match(/^\/api\/assignments\/([^/]+)\/submissions\/([^/]+)$/);
  if (gradeMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const [, assignmentId, studentId] = gradeMatch;
    const { status, remark } = await request.json();
    if (status && !SUBMISSION_STATUSES.includes(status)) {
      return json({ error: "Invalid status." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const row = await env.DB
        .prepare(`SELECT c.level FROM assignments a JOIN classes c ON c.id = a.class_id WHERE a.id = ?`)
        .bind(assignmentId)
        .first();
      if (!row || row.level !== restriction) return json({ error: "Not authorised for this assignment." }, 403);
    }

    const existing = await env.DB
      .prepare("SELECT id FROM assignment_submissions WHERE assignment_id = ? AND student_id = ?")
      .bind(assignmentId, studentId)
      .first();

    if (existing) {
      await env.DB
        .prepare(
          `UPDATE assignment_submissions SET status = COALESCE(?, status), remark = ?
           WHERE assignment_id = ? AND student_id = ?`
        )
        .bind(status || null, remark || null, assignmentId, studentId)
        .run();
    } else {
      await env.DB
        .prepare(
          `INSERT INTO assignment_submissions (id, assignment_id, student_id, status, remark)
           VALUES (?, ?, ?, ?, ?)`
        )
        .bind(uuid(), assignmentId, studentId, status || "graded", remark || null)
        .run();
    }

    return json({ message: "Submission updated." });
  }

  // ---------------- DELETE ASSIGNMENT ----------------
  if (detailMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const assignmentId = detailMatch[1];
    const assignment = await env.DB
      .prepare("SELECT id FROM assignments WHERE id = ?")
      .bind(assignmentId)
      .first();
    if (!assignment) return json({ error: "Assignment not found." }, 404);

    await env.DB
      .prepare("DELETE FROM assignment_submissions WHERE assignment_id = ?")
      .bind(assignmentId)
      .run();
    await env.DB
      .prepare("DELETE FROM assignments WHERE id = ?")
      .bind(assignmentId)
      .run();

    return json({ message: "Assignment deleted." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7B: Roster routes (Classes & Students)
// =====================================================================
/**
 * FIS Itobe Portal — Worker API (Roster: Classes & Students)
 *
 * Routes:
 *   GET  /api/classes                  (auth: teaching staff) list all classes
 *   POST /api/classes                  (auth: admin) create a class { name, level, sortOrder }
 *   GET  /api/students?classId=        (auth: teaching staff) list active students in a class
 *   POST /api/students                 (auth: admin) create a student — admission number is
 *        generated by the system, not supplied by the client
 *        body: { name, classId, level, sessionJoined, guardianName, guardianPhone }
 *   POST /api/students/:id/pin         (auth: admin) generate a login PIN for a student for a
 *        given term/session — required before that student can sign in
 *        body: { term, session }
 *   GET  /api/subjects                 (auth: teaching staff) list subjects, optional ?level=
 *   POST /api/subjects                 (auth: admin) create a subject { name, level }
 *   GET  /api/classes/:classId/subjects       (auth: teaching staff) list subjects assigned to a class
 *   POST /api/classes/:classId/subjects       (auth: admin) assign a subject { subjectId }
 *   DELETE /api/classes/:classId/subjects/:subjectId  (auth: admin) unassign a subject
 *   GET  /api/classes/:classId/pin-status?term=&session=  (auth: admin) per-student
 *        has-a-pin flag for that term/session, used to skip or flag already-assigned PINs
 *   PATCH  /api/classes/:id           (auth: admin) set which class this one promotes into
 *        body: { nextClassId }        (null/omit to clear)
 *   POST /api/classes/:id/promote     (auth: admin) bulk-move selected active students out of
 *        this class — into another class, or (if toClassId omitted) mark them status='graduated'
 *        body: { studentIds: [...], toClassId? }
 *   DELETE /api/classes/:id           (auth: admin) delete a class (must have no active students)
 *   DELETE /api/subjects/:id          (auth: admin) delete a subject
 *   DELETE /api/students/:id          (auth: admin) soft-delete a student (sets status to inactive,
 *        preserving their attendance/assignment/PIN history)
 *   PATCH  /api/students/:id          (auth: admin) edit an active student's core details
 *        body: { name, classId, sessionJoined, guardianName, guardianPhone }
 */

/**
 * Generates the next admission number in the school's existing format,
 * FISS/<year>/<4-digit sequence>, e.g. FISS/2026/0001. The sequence resets
 * per calendar year, scanning existing admission numbers for that year.
 */
async function generateAdmissionNo(env) {
  const year = new Date().getFullYear();
  const prefix = `FISS/${year}/`;

  const { results } = await env.DB
    .prepare("SELECT admission_no FROM students WHERE admission_no LIKE ? ORDER BY admission_no DESC LIMIT 1")
    .bind(prefix + "%")
    .all();

  let nextSeq = 1;
  if (results.length) {
    const lastNo = results[0].admission_no;
    const seqPart = lastNo.split("/").pop();
    const seqNum = parseInt(seqPart, 10);
    if (!isNaN(seqNum)) nextSeq = seqNum + 1;
  }

  return prefix + String(nextSeq).padStart(4, "0");
}

/**
 * Generates a random 6-digit numeric PIN as a string, e.g. "048273".
 * (Hardened from an earlier 4-digit PIN — a 6-digit PIN plus the lockout
 * in handleStudentAuthRoutes makes brute-forcing impractical.)
 */
function generatePin() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function handleRosterRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- LIST CLASSES ----------------
  if (pathname === "/api/classes" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const restriction = adminLevelRestriction(sessionCtx);
    const level = restriction || url.searchParams.get("level");
    const stmt = level
      ? env.DB.prepare("SELECT * FROM classes WHERE level = ? ORDER BY sort_order, name").bind(level)
      : env.DB.prepare("SELECT * FROM classes ORDER BY level, sort_order, name");

    const { results } = await stmt.all();
    return json({ classes: results });
  }

  // ---------------- CREATE CLASS ----------------
  if (pathname === "/api/classes" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { name, level, sortOrder } = await request.json();
    if (!name || !level) {
      return json({ error: "name and level are required." }, 400);
    }
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && level !== restriction) {
      return json({ error: `As a ${restriction} admin, you can only create ${restriction} classes.` }, 403);
    }

    const id = uuid();
    await env.DB
      .prepare(`INSERT INTO classes (id, name, level, sort_order) VALUES (?, ?, ?, ?)`)
      .bind(id, name, level, sortOrder || 0)
      .run();

    return json({ message: "Class created.", id });
  }

  // ---------------- LIST STUDENTS ----------------
  if (pathname === "/api/students" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const restriction = adminLevelRestriction(sessionCtx);
    const classId = url.searchParams.get("classId");

    if (classId && restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    let stmt;
    if (classId) {
      stmt = env.DB.prepare("SELECT * FROM students WHERE class_id = ? AND status = 'active' ORDER BY name COLLATE NOCASE").bind(classId);
    } else if (restriction) {
      stmt = env.DB.prepare("SELECT * FROM students WHERE status = 'active' AND level = ? ORDER BY name COLLATE NOCASE").bind(restriction);
    } else {
      stmt = env.DB.prepare("SELECT * FROM students WHERE status = 'active' ORDER BY name COLLATE NOCASE");
    }

    const { results } = await stmt.all();
    return json({ students: results });
  }

  // ---------------- SCAN CLASS LIST PHOTO (AI reader) ----------------
  if (pathname === "/api/scan-roster" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);
    return scanRosterImage(request, env);
  }

  // ---------------- CREATE STUDENT ----------------
  if (pathname === "/api/students" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { name, classId, level, sessionJoined, guardianName, guardianPhone } = await request.json();
    if (!name || !classId || !level) {
      return json({ error: "name, classId, and level are required." }, 400);
    }
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && level !== restriction) {
      return json({ error: `As a ${restriction} admin, you can only add ${restriction} students.` }, 403);
    }

    const admissionNo = await generateAdmissionNo(env);
    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO students (id, admission_no, name, class_id, level, session_joined, guardian_name, guardian_phone, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', datetime('now'))`
      )
      .bind(id, admissionNo, name, classId, level, sessionJoined || null, guardianName || null, guardianPhone || null)
      .run();

    return json({ message: "Student added.", id, admissionNo });
  }

  // ---------------- STUDENT PHOTO: SAVE / CLEAR URL (photo file itself lives in Firebase Storage) ----------------
  const photoMatch = pathname.match(/^\/api\/students\/([^/]+)\/photo$/);
  if (photoMatch) {
    const studentId = photoMatch[1];
    const sessionCtx = await getSession(request, env);
    const isSelf = sessionCtx && sessionCtx.type === "student" && sessionCtx.id === studentId;
    if (!isSelf && !isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const student = await env.DB
      .prepare("SELECT id, level FROM students WHERE id = ?")
      .bind(studentId)
      .first();
    if (!student) return json({ error: "Student not found." }, 404);

    if (!isSelf) {
      const restriction = adminLevelRestriction(sessionCtx);
      if (restriction && student.level !== restriction) {
        return json({ error: "Not authorised for this student." }, 403);
      }
    }

    if (request.method === "PATCH") {
      const { photoUrl } = await request.json();
      if (!photoUrl || typeof photoUrl !== "string") {
        return json({ error: "photoUrl is required." }, 400);
      }
      await env.DB.prepare("UPDATE students SET photo_key = ? WHERE id = ?").bind(photoUrl, studentId).run();
      return json({ message: "Photo saved." });
    }

    if (request.method === "DELETE") {
      await env.DB.prepare("UPDATE students SET photo_key = NULL WHERE id = ?").bind(studentId).run();
      return json({ message: "Photo removed." });
    }
  }

  // ---------------- GENERATE STUDENT PIN ----------------
  const pinMatch = pathname.match(/^\/api\/students\/([^/]+)\/pin$/);
  if (pinMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const studentId = pinMatch[1];
    const { term, session } = await request.json();
    if (!term || !session) {
      return json({ error: "term and session are required." }, 400);
    }

    const student = await env.DB
      .prepare("SELECT id, level FROM students WHERE id = ? AND status = 'active'")
      .bind(studentId)
      .first();
    if (!student) return json({ error: "Student not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && student.level !== restriction) {
      return json({ error: "Not authorised for this student." }, 403);
    }

    const pin = generatePin();
    const pinHash = await hash(pin);
    const pinEnc = await encryptPin(pin, env);

    const existing = await env.DB
      .prepare("SELECT id FROM student_pins WHERE student_id = ? AND term = ? AND session = ?")
      .bind(studentId, term, session)
      .first();

    if (existing) {
      await env.DB
        .prepare(
          `UPDATE student_pins SET pin_hash = ?, pin_enc = ?, generated_at = datetime('now'), failed_attempts = 0, locked_until = NULL
           WHERE student_id = ? AND term = ? AND session = ?`
        )
        .bind(pinHash, pinEnc, studentId, term, session)
        .run();
    } else {
      await env.DB
        .prepare(
          `INSERT INTO student_pins (id, student_id, pin_hash, pin_enc, term, session, generated_at)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
        )
        .bind(uuid(), studentId, pinHash, pinEnc, term, session)
        .run();
    }

    // A PIN is only ever valid for the term/session it was issued for.
    // The moment a student is issued a PIN for this term, retire every
    // other term/session's PIN for that student — the row is gone, so a
    // login attempt against an old term now gets "No PIN has been
    // generated for this term/session yet." instead of succeeding.
    await env.DB
      .prepare("DELETE FROM student_pins WHERE student_id = ? AND NOT (term = ? AND session = ?)")
      .bind(studentId, term, session)
      .run();

    return json({ message: "PIN generated.", pin, term, session });
  }

  // ---------------- FETCH EXISTING STUDENT PIN (for reprinting) ----------------
  // Same route as PIN generation above, but GET: returns the PIN already on
  // file for this term/session (decrypted) without creating a new one, so
  // an admin can reprint a slip without changing the student's actual PIN.
  if (pinMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const studentId = pinMatch[1];
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!term || !session) {
      return json({ error: "term and session are required." }, 400);
    }

    const student = await env.DB
      .prepare("SELECT id, level FROM students WHERE id = ? AND status = 'active'")
      .bind(studentId)
      .first();
    if (!student) return json({ error: "Student not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && student.level !== restriction) {
      return json({ error: "Not authorised for this student." }, 403);
    }

    const pinRow = await env.DB
      .prepare("SELECT pin_enc FROM student_pins WHERE student_id = ? AND term = ? AND session = ?")
      .bind(studentId, term, session)
      .first();
    if (!pinRow) return json({ error: "No PIN has been generated for this term/session yet." }, 404);

    const pin = await decryptPin(pinRow.pin_enc, env);
    if (!pin) {
      return json(
        { error: "This PIN predates reprinting support and can't be recovered — regenerate it." },
        404
      );
    }

    return json({ pin, term, session });
  }

  // ---------------- LIST SUBJECTS ----------------
  if (pathname === "/api/subjects" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const restriction = adminLevelRestriction(sessionCtx);
    const level = restriction || url.searchParams.get("level");
    const stmt = level
      ? env.DB.prepare("SELECT * FROM subjects WHERE level = ? ORDER BY name").bind(level)
      : env.DB.prepare("SELECT * FROM subjects ORDER BY level, name");

    const { results } = await stmt.all();
    return json({ subjects: results });
  }

  // ---------------- CREATE SUBJECT ----------------
  if (pathname === "/api/subjects" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { name, level } = await request.json();
    if (!name || !level) {
      return json({ error: "name and level are required." }, 400);
    }
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && level !== restriction) {
      return json({ error: `As a ${restriction} admin, you can only create ${restriction} subjects.` }, 403);
    }

    const id = uuid();
    await env.DB
      .prepare(`INSERT INTO subjects (id, name, level) VALUES (?, ?, ?)`)
      .bind(id, name, level)
      .run();

    return json({ message: "Subject created.", id });
  }

  // ---------------- LIST SUBJECTS ASSIGNED TO A CLASS ----------------
  const classSubjectsMatch = pathname.match(/^\/api\/classes\/([^/]+)\/subjects$/);
  if (classSubjectsMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = classSubjectsMatch[1];
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT s.id, s.name, s.level
         FROM class_subjects cs
         JOIN subjects s ON s.id = cs.subject_id
         WHERE cs.class_id = ?
         ORDER BY s.name`
      )
      .bind(classId)
      .all();

    return json({ classId, subjects: results });
  }

  // ---------------- ASSIGN A SUBJECT TO A CLASS ----------------
  if (classSubjectsMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = classSubjectsMatch[1];
    const { subjectId } = await request.json();
    if (!subjectId) return json({ error: "subjectId is required." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    await env.DB
      .prepare("INSERT OR IGNORE INTO class_subjects (class_id, subject_id) VALUES (?, ?)")
      .bind(classId, subjectId)
      .run();

    return json({ message: "Subject assigned to class." });
  }

  // ---------------- UNASSIGN A SUBJECT FROM A CLASS ----------------
  const unassignMatch = pathname.match(/^\/api\/classes\/([^/]+)\/subjects\/([^/]+)$/);
  if (unassignMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const [, classId, subjectId] = unassignMatch;
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    await env.DB
      .prepare("DELETE FROM class_subjects WHERE class_id = ? AND subject_id = ?")
      .bind(classId, subjectId)
      .run();

    return json({ message: "Subject removed from class." });
  }

  // ---------------- PIN STATUS FOR A CLASS (term/session) ----------------
  const pinStatusMatch = pathname.match(/^\/api\/classes\/([^/]+)\/pin-status$/);
  if (pinStatusMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = pinStatusMatch[1];
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!term || !session) {
      return json({ error: "term and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT s.id, s.name, s.admission_no,
                CASE WHEN sp.id IS NOT NULL THEN 1 ELSE 0 END AS has_pin,
                sp.pin_enc AS pin_enc
         FROM students s
         LEFT JOIN student_pins sp
           ON sp.student_id = s.id AND sp.term = ? AND sp.session = ?
         WHERE s.class_id = ? AND s.status = 'active'
         ORDER BY s.name COLLATE NOCASE`
      )
      .bind(term, session, classId)
      .all();

    // Decrypt each existing PIN so an already-assigned student can still
    // be shown/printed without needing a fresh PIN generated.
    const students = await Promise.all(
      results.map(async (r) => ({
        id: r.id,
        name: r.name,
        admission_no: r.admission_no,
        has_pin: r.has_pin,
        pin: r.has_pin ? await decryptPin(r.pin_enc, env) : null
      }))
    );

    return json({ classId, term, session, students });
  }

  // ---------------- DELETE CLASS ----------------
  const classDetailMatch = pathname.match(/^\/api\/classes\/([^/]+)$/);
  if (classDetailMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = classDetailMatch[1];
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const studentCount = await env.DB
      .prepare("SELECT COUNT(*) AS count FROM students WHERE class_id = ? AND status = 'active'")
      .bind(classId)
      .first();
    if (studentCount && studentCount.count > 0) {
      return json({ error: "This class still has students in it. Move or remove them first." }, 409);
    }

    await env.DB.prepare("DELETE FROM class_subjects WHERE class_id = ?").bind(classId).run();
    await env.DB.prepare("DELETE FROM classes WHERE id = ?").bind(classId).run();

    return json({ message: "Class deleted." });
  }

  // ---------------- SET NEXT CLASS (used by Promotion) ----------------
  if (classDetailMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = classDetailMatch[1];
    const cls = await env.DB.prepare("SELECT id, level FROM classes WHERE id = ?").bind(classId).first();
    if (!cls) return json({ error: "Class not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && cls.level !== restriction) {
      return json({ error: "Not authorised for this class." }, 403);
    }

    const { nextClassId } = await request.json();
    let normalizedNextClassId = null;
    if (nextClassId) {
      if (nextClassId === classId) {
        return json({ error: "A class can't promote into itself." }, 400);
      }
      const target = await env.DB.prepare("SELECT id FROM classes WHERE id = ?").bind(nextClassId).first();
      if (!target) return json({ error: "Target class not found." }, 404);
      normalizedNextClassId = nextClassId;
    }

    await env.DB.prepare("UPDATE classes SET next_class_id = ? WHERE id = ?").bind(normalizedNextClassId, classId).run();
    return json({ message: "Saved." });
  }

  // ---------------- PROMOTE STUDENTS ----------------
  const promoteMatch = pathname.match(/^\/api\/classes\/([^/]+)\/promote$/);
  if (promoteMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const fromClassId = promoteMatch[1];
    const fromClass = await env.DB.prepare("SELECT id, level, name FROM classes WHERE id = ?").bind(fromClassId).first();
    if (!fromClass) return json({ error: "Class not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && fromClass.level !== restriction) {
      return json({ error: "Not authorised for this class." }, 403);
    }

    const { studentIds, toClassId } = await request.json();
    if (!Array.isArray(studentIds) || !studentIds.length) {
      return json({ error: "Select at least one student to promote." }, 400);
    }

    let toClass = null;
    if (toClassId) {
      toClass = await env.DB.prepare("SELECT id, level, name FROM classes WHERE id = ?").bind(toClassId).first();
      if (!toClass) return json({ error: "Destination class not found." }, 404);
      if (toClass.id === fromClass.id) {
        return json({ error: "Destination class must be different from the current class." }, 400);
      }
      if (restriction && toClass.level !== restriction) {
        return json({ error: `As a ${restriction} admin, you can only promote into ${restriction} classes.` }, 403);
      }
    }

    // Only touch students who are actually still active in the stated class —
    // guards against a stale checklist promoting/graduating the wrong students.
    const placeholders = studentIds.map(() => "?").join(",");
    const { results: eligible } = await env.DB
      .prepare(`SELECT id FROM students WHERE class_id = ? AND status = 'active' AND id IN (${placeholders})`)
      .bind(fromClassId, ...studentIds)
      .all();

    if (!eligible.length) {
      return json({ error: "None of the selected students are currently active in this class." }, 409);
    }

    const eligibleIds = eligible.map(s => s.id);
    const idPlaceholders = eligibleIds.map(() => "?").join(",");

    if (toClass) {
      await env.DB
        .prepare(`UPDATE students SET class_id = ?, level = ? WHERE id IN (${idPlaceholders})`)
        .bind(toClass.id, toClass.level, ...eligibleIds)
        .run();
      return json({
        message: `${eligibleIds.length} student(s) promoted from ${fromClass.name} to ${toClass.name}.`,
        promoted: eligibleIds.length
      });
    }

    // No destination class — this is the graduating class; students become alumni
    // and drop off active rosters, same as the soft-delete status but distinguishable.
    await env.DB
      .prepare(`UPDATE students SET status = 'graduated' WHERE id IN (${idPlaceholders})`)
      .bind(...eligibleIds)
      .run();
    return json({
      message: `${eligibleIds.length} student(s) graduated from ${fromClass.name}.`,
      graduated: eligibleIds.length
    });
  }

  // ---------------- DELETE SUBJECT ----------------
  const subjectDetailMatch = pathname.match(/^\/api\/subjects\/([^/]+)$/);
  if (subjectDetailMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const subjectId = subjectDetailMatch[1];
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const subj = await env.DB.prepare("SELECT level FROM subjects WHERE id = ?").bind(subjectId).first();
      if (!subj || subj.level !== restriction) return json({ error: "Not authorised for this subject." }, 403);
    }

    await env.DB.prepare("DELETE FROM class_subjects WHERE subject_id = ?").bind(subjectId).run();
    await env.DB.prepare("DELETE FROM subjects WHERE id = ?").bind(subjectId).run();

    return json({ message: "Subject deleted." });
  }

  // ---------------- EDIT / REMOVE STUDENT ----------------
  const studentDetailMatch = pathname.match(/^\/api\/students\/([^/]+)$/);

  if (studentDetailMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const studentId = studentDetailMatch[1];
    const student = await env.DB
      .prepare("SELECT id, level FROM students WHERE id = ? AND status = 'active'")
      .bind(studentId)
      .first();
    if (!student) return json({ error: "Student not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && student.level !== restriction) {
      return json({ error: "Not authorised for this student." }, 403);
    }

    const { name, classId, sessionJoined, guardianName, guardianPhone, dob } = await request.json();
    if (!name || !classId) {
      return json({ error: "name and classId are required." }, 400);
    }

    // If moving the student to a different class, that class must be within
    // the admin's level restriction too (a level admin can't move a student
    // into the other level's class).
    let newLevel = student.level;
    const targetClass = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
    if (!targetClass) return json({ error: "Class not found." }, 404);
    if (restriction && targetClass.level !== restriction) {
      return json({ error: `As a ${restriction} admin, you can only assign ${restriction} classes.` }, 403);
    }
    newLevel = targetClass.level;

    await env.DB
      .prepare(
        `UPDATE students SET name = ?, class_id = ?, level = ?, session_joined = ?, guardian_name = ?, guardian_phone = ?, dob = ?
         WHERE id = ?`
      )
      .bind(name, classId, newLevel, sessionJoined || null, guardianName || null, guardianPhone || null, dob || null, studentId)
      .run();

    return json({ message: "Student updated." });
  }

  if (studentDetailMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const studentId = studentDetailMatch[1];
    const student = await env.DB
      .prepare("SELECT id, level FROM students WHERE id = ? AND status = 'active'")
      .bind(studentId)
      .first();
    if (!student) return json({ error: "Student not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && student.level !== restriction) {
      return json({ error: "Not authorised for this student." }, 403);
    }

    await env.DB
      .prepare("UPDATE students SET status = 'inactive' WHERE id = ?")
      .bind(studentId)
      .run();

    return json({ message: "Student removed." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7B2: Teacher assignment routes (which teacher handles which
// class + subject)
// =====================================================================
/**
 * Routes:
 *   GET  /api/teachers                          (auth: admin) list active teachers
 *   POST /api/teacher-assignments               (auth: admin) { teacherId, classId, subjectId }
 *   GET  /api/teacher-assignments?teacherId=&classId=   (auth: admin) list assignments, joined with names
 *   DELETE /api/teacher-assignments/:id         (auth: admin) remove one assignment
 */
async function handleTeacherAssignmentRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- LIST TEACHERS ----------------
  if (pathname === "/api/teachers" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    // A genuine primary_admin/secondary_admin account is always scoped to its
    // own level. A general_admin has no fixed restriction, but the frontend's
    // Primary View / Secondary View / Overview toggle passes ?level= so the
    // list still follows whichever level they're currently viewing.
    const restriction = adminLevelRestriction(sessionCtx) || url.searchParams.get("level");
    const stmt = restriction
      ? env.DB.prepare("SELECT id, name, email, level FROM users WHERE role = 'teacher' AND status = 'active' AND level = ? ORDER BY name").bind(restriction)
      : env.DB.prepare("SELECT id, name, email, level FROM users WHERE role = 'teacher' AND status = 'active' ORDER BY name");

    const { results } = await stmt.all();
    return json({ teachers: results });
  }

  // ---------------- ASSIGN A TEACHER TO A CLASS + SUBJECT ----------------
  if (pathname === "/api/teacher-assignments" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { teacherId, classId, subjectId } = await request.json();
    if (!teacherId || !classId || !subjectId) {
      return json({ error: "teacherId, classId, and subjectId are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const teacher = await env.DB
      .prepare("SELECT id, level FROM users WHERE id = ? AND role = 'teacher' AND status = 'active'")
      .bind(teacherId)
      .first();
    if (!teacher) return json({ error: "Teacher not found." }, 404);
    if (restriction && teacher.level !== restriction) {
      return json({ error: "Not authorised for this teacher." }, 403);
    }

    const validPair = await env.DB
      .prepare("SELECT 1 FROM class_subjects WHERE class_id = ? AND subject_id = ?")
      .bind(classId, subjectId)
      .first();
    if (!validPair) {
      return json({ error: "That subject is not assigned to this class yet." }, 400);
    }

    const existing = await env.DB
      .prepare("SELECT id FROM teacher_assignments WHERE teacher_id = ? AND class_id = ? AND subject_id = ?")
      .bind(teacherId, classId, subjectId)
      .first();
    if (existing) {
      return json({ error: "This teacher is already assigned to that class and subject." }, 409);
    }

    const id = uuid();
    await env.DB
      .prepare("INSERT INTO teacher_assignments (id, teacher_id, class_id, subject_id) VALUES (?, ?, ?, ?)")
      .bind(id, teacherId, classId, subjectId)
      .run();

    return json({ message: "Teacher assigned.", id });
  }

  // ---------------- LIST ASSIGNMENTS ----------------
  if (pathname === "/api/teacher-assignments" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const teacherId = url.searchParams.get("teacherId");
    const classId = url.searchParams.get("classId");

    // Non-admin (teacher) sessions may only ever look up their own assignments.
    if (!isAdminSession(sessionCtx)) {
      if (!teacherId || teacherId !== sessionCtx.id) {
        return json({ error: "You may only view your own assignments." }, 403);
      }
    }

    const restriction = adminLevelRestriction(sessionCtx);

    let query = `
      SELECT ta.id, ta.teacher_id, u.name AS teacher_name,
             ta.class_id, c.name AS class_name,
             ta.subject_id, s.name AS subject_name
      FROM teacher_assignments ta
      JOIN users u ON u.id = ta.teacher_id
      JOIN classes c ON c.id = ta.class_id
      JOIN subjects s ON s.id = ta.subject_id
    `;
    const conditions = [];
    const params = [];
    if (teacherId) { conditions.push("ta.teacher_id = ?"); params.push(teacherId); }
    if (classId) { conditions.push("ta.class_id = ?"); params.push(classId); }
    if (restriction) { conditions.push("c.level = ?"); params.push(restriction); }
    if (conditions.length) query += " WHERE " + conditions.join(" AND ");
    query += " ORDER BY c.sort_order, s.name";

    const { results } = await env.DB.prepare(query).bind(...params).all();
    return json({ assignments: results });
  }

  // ---------------- REMOVE AN ASSIGNMENT ----------------
  const assignmentDetailMatch = pathname.match(/^\/api\/teacher-assignments\/([^/]+)$/);
  if (assignmentDetailMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const assignmentId = assignmentDetailMatch[1];
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const row = await env.DB
        .prepare(
          `SELECT c.level FROM teacher_assignments ta JOIN classes c ON c.id = ta.class_id WHERE ta.id = ?`
        )
        .bind(assignmentId)
        .first();
      if (!row || row.level !== restriction) return json({ error: "Not authorised for this assignment." }, 403);
    }

    await env.DB.prepare("DELETE FROM teacher_assignments WHERE id = ?").bind(assignmentId).run();

    return json({ message: "Assignment removed." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7D: Admissions routes (public apply form + admin review)
// =====================================================================
/**
 * Routes:
 *   POST /api/admissions/apply                (public, no auth) submit an application
 *   GET  /api/admissions?status=&level=       (auth: admin) list applications
 *   PATCH /api/admissions/:id                 (auth: admin) { action: 'approve'|'reject', classId }
 *        approve creates the student record + admission number automatically
 */
async function handleAdmissionRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- PUBLIC: SUBMIT APPLICATION ----------------
  if (pathname === "/api/admissions/apply" && request.method === "POST") {
    const body = await request.json();
    const {
      studentName, dob, gender, levelApplied, classApplied,
      guardianName, guardianPhone, guardianEmail, address,
      priorSchool, healthNotes, photoUrl
    } = body;

    if (!studentName || !levelApplied || !guardianName || !guardianPhone) {
      return json({ error: "studentName, levelApplied, guardianName, and guardianPhone are required." }, 400);
    }

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO admission_applications
           (id, student_name, dob, gender, level_applied, class_applied,
            guardian_name, guardian_phone, guardian_email, address,
            prior_school, health_notes, photo_url, raw_form_json, status, submitted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))`
      )
      .bind(
        id, studentName, dob || null, gender || null, levelApplied, classApplied || null,
        guardianName, guardianPhone, guardianEmail || null, address || null,
        priorSchool || null, healthNotes || null, photoUrl || null, JSON.stringify(body)
      )
      .run();

    return json({ message: "Application submitted. The school will contact you after review.", id });
  }

  // ---------------- ADMIN: LIST APPLICATIONS ----------------
  if (pathname === "/api/admissions" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const status = url.searchParams.get("status") || "pending";
    const restriction = adminLevelRestriction(sessionCtx);
    const level = restriction || url.searchParams.get("level");

    let query = `
      SELECT aa.id, aa.student_name, aa.dob, aa.gender, aa.level_applied, aa.class_applied,
             aa.guardian_name, aa.guardian_phone, aa.guardian_email, aa.address,
             aa.prior_school, aa.health_notes, aa.photo_url, aa.status, aa.admission_no, aa.assigned_class,
             c.name AS assigned_class_name,
             aa.submitted_at, aa.decided_by, aa.decided_at
      FROM admission_applications aa
      LEFT JOIN classes c ON c.id = aa.assigned_class
      WHERE aa.status = ?
    `;
    const params = [status];
    if (level) { query += " AND aa.level_applied = ?"; params.push(level); }
    query += " ORDER BY aa.submitted_at DESC";

    const { results } = await env.DB.prepare(query).bind(...params).all();
    return json({ applications: results });
  }

  // ---------------- ADMIN: DECIDE (APPROVE / REJECT) ----------------
  const decisionMatch = pathname.match(/^\/api\/admissions\/([^/]+)$/);
  if (decisionMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const applicationId = decisionMatch[1];
    const { action, classId } = await request.json();
    if (!["approve", "reject"].includes(action)) {
      return json({ error: "action must be 'approve' or 'reject'." }, 400);
    }

    const application = await env.DB
      .prepare("SELECT * FROM admission_applications WHERE id = ? AND status = 'pending'")
      .bind(applicationId)
      .first();
    if (!application) return json({ error: "Pending application not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && application.level_applied !== restriction) {
      return json({ error: "Not authorised for this application." }, 403);
    }

    if (action === "reject") {
      await env.DB
        .prepare(
          `UPDATE admission_applications SET status = 'rejected', decided_by = ?, decided_at = datetime('now')
           WHERE id = ?`
        )
        .bind(sessionCtx.id, applicationId)
        .run();

      return json({ message: "Application rejected." });
    }

    // action === "approve"
    if (!classId) return json({ error: "classId is required to approve an application." }, 400);

    const targetClass = await env.DB
      .prepare("SELECT id, level FROM classes WHERE id = ?")
      .bind(classId)
      .first();
    if (!targetClass) return json({ error: "Class not found." }, 404);
    if (restriction && targetClass.level !== restriction) {
      return json({ error: "Not authorised for this class." }, 403);
    }

    const admissionNo = await generateAdmissionNo(env);
    const studentId = uuid();

    await env.DB
      .prepare(
        `INSERT INTO students (id, admission_no, name, class_id, level, guardian_name, guardian_phone, photo_key, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', datetime('now'))`
      )
      .bind(studentId, admissionNo, application.student_name, classId, targetClass.level, application.guardian_name, application.guardian_phone, application.photo_url || null)
      .run();

    await env.DB
      .prepare(
        `UPDATE admission_applications
         SET status = 'approved', admission_no = ?, assigned_class = ?, decided_by = ?, decided_at = datetime('now')
         WHERE id = ?`
      )
      .bind(admissionNo, classId, sessionCtx.id, applicationId)
      .run();

    return json({ message: "Application approved and student enrolled.", admissionNo, studentId });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7E: Manage Accounts routes (admin view/edit/suspend/reset/
// delete existing staff accounts — separate from Approvals, which
// only handles brand-new pending signups)
// =====================================================================
/**
 * Routes:
 *   GET    /api/staff                    (auth: admin) list all non-pending staff accounts
 *   PATCH  /api/staff/:id                (auth: admin) { role, level } change role/level
 *   PATCH  /api/staff/:id/dob            (auth: admin) { dob: 'YYYY-MM-DD' } staff birthday for the birthday list
 *   PATCH  /api/staff/:id/status         (auth: admin) { status: 'active'|'suspended' }
 *   POST   /api/staff/:id/reset-password (auth: admin) generates + returns a new temporary password
 *   DELETE /api/staff/:id                (auth: admin) permanently remove the account
 */
const VALID_STAFF_ROLES = ["teacher", "cashier", "primary_admin", "secondary_admin", "general_admin"];

function generateTempPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  let out = "";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  for (let i = 0; i < bytes.length; i++) out += chars[bytes[i] % chars.length];
  return out;
}

async function handleManageAccountsRoutes(request, env, url) {
  const { pathname } = url;

  function isGeneralAdmin(session) {
    return !!session && session.type === "staff" && session.role === "general_admin";
  }

  // ---------------- LIST ALL STAFF ----------------
  if (pathname === "/api/staff" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. Only the General Admin can manage accounts." }, 403);

    const { results } = await env.DB
      .prepare(
        `SELECT id, name, email, phone, dob, role, level, status, created_at, approved_by, approved_at
         FROM users WHERE status IN ('active', 'suspended') ORDER BY name`
      )
      .all();

    return json({ staff: results });
  }

  // ---------------- CHANGE ROLE / LEVEL ----------------
  const roleMatch = pathname.match(/^\/api\/staff\/([^/]+)$/);
  if (roleMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. Only the General Admin can manage accounts." }, 403);

    const staffId = roleMatch[1];
    const { role, level } = await request.json();

    if (!VALID_STAFF_ROLES.includes(role)) {
      return json({ error: "Invalid role." }, 400);
    }

    const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(staffId).first();
    if (!target) return json({ error: "Account not found." }, 404);

    await env.DB
      .prepare("UPDATE users SET role = ?, level = ? WHERE id = ?")
      .bind(role, level || null, staffId)
      .run();

    return json({ message: "Account updated." });
  }

  // ---------------- SET/UPDATE PHONE (used for SMS notifications) ----------------
  const phoneMatch = pathname.match(/^\/api\/staff\/([^/]+)\/phone$/);
  if (phoneMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. Only the General Admin can manage accounts." }, 403);

    const staffId = phoneMatch[1];
    const { phone } = await request.json();

    const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(staffId).first();
    if (!target) return json({ error: "Account not found." }, 404);

    await env.DB.prepare("UPDATE users SET phone = ? WHERE id = ?").bind(phone ? String(phone).trim() : null, staffId).run();

    return json({ message: "Phone number saved." });
  }

  // ---------------- SET/UPDATE DATE OF BIRTH (drives the staff birthday list) ----------------
  const dobMatch = pathname.match(/^\/api\/staff\/([^/]+)\/dob$/);
  if (dobMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. Only the General Admin can manage accounts." }, 403);

    const staffId = dobMatch[1];
    const { dob } = await request.json();
    if (dob && !/^\d{4}-\d{2}-\d{2}$/.test(String(dob))) {
      return json({ error: "Date of birth must be a valid date (YYYY-MM-DD)." }, 400);
    }

    const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(staffId).first();
    if (!target) return json({ error: "Account not found." }, 404);

    await env.DB.prepare("UPDATE users SET dob = ? WHERE id = ?").bind(dob || null, staffId).run();
    return json({ message: "Date of birth saved." });
  }

  // ---------------- SUSPEND / REACTIVATE ----------------
  const statusMatch = pathname.match(/^\/api\/staff\/([^/]+)\/status$/);
  if (statusMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. Only the General Admin can manage accounts." }, 403);

    const staffId = statusMatch[1];
    const { status } = await request.json();

    if (!["active", "suspended"].includes(status)) {
      return json({ error: "status must be 'active' or 'suspended'." }, 400);
    }
    if (staffId === sessionCtx.id) {
      return json({ error: "You can't suspend your own account." }, 400);
    }

    const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(staffId).first();
    if (!target) return json({ error: "Account not found." }, 404);

    await env.DB.prepare("UPDATE users SET status = ? WHERE id = ?").bind(status, staffId).run();

    return json({ message: status === "suspended" ? "Account suspended." : "Account reactivated." });
  }

  // ---------------- RESET PASSWORD ----------------
  const resetMatch = pathname.match(/^\/api\/staff\/([^/]+)\/reset-password$/);
  if (resetMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. Only the General Admin can manage accounts." }, 403);

    const staffId = resetMatch[1];
    const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(staffId).first();
    if (!target) return json({ error: "Account not found." }, 404);

    const tempPassword = generateTempPassword();
    const passwordHash = await hash(tempPassword);

    await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(passwordHash, staffId).run();

    return json({ message: "Password reset.", tempPassword });
  }

  // ---------------- DELETE ACCOUNT ----------------
  const deleteMatch = pathname.match(/^\/api\/staff\/([^/]+)$/);
  if (deleteMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. Only the General Admin can manage accounts." }, 403);

    const staffId = deleteMatch[1];
    if (staffId === sessionCtx.id) {
      return json({ error: "You can't delete your own account." }, 400);
    }

    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(staffId).run();

    return json({ message: "Account deleted." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7F: Fees routes (fee structure per class/term + payment
// logging + balances + collection totals)
// =====================================================================
/**
 * Routes:
 *   POST /api/fee-structures                  (auth: admin) set/update the fee amount for a class/term/session
 *   GET  /api/fee-structures?term=&session=   (auth: cashier/admin) list fee amount per class for a term
 *   POST /api/fees/payments                   (auth: cashier/admin) record a payment — ALWAYS live, never queued offline
 *   GET  /api/fees/student/:studentId?term=&session=  (auth: cashier/admin, or the student viewing their own) fee owed, paid, balance, and payment history
 *   GET  /api/fees/class/:classId?term=&session=      (auth: cashier/admin) per-student paid/balance for a class
 *   GET  /api/fees/totals?term=&session=              (auth: cashier/admin) amount collected today/this week/this month/this term
 */
function isFeeStaff(session) {
  return isStaff(session) && ["cashier", "general_admin", "primary_admin", "secondary_admin"].includes(session.role);
}


// Receipt numbers are saved with each payment (fee_transactions.receipt_seq) and
// shown as FIS-RCT-000123. Old payments are numbered once by the migration SQL.
function formatReceiptNo(seq) {
  return seq ? "FIS-RCT-" + String(seq).padStart(6, "0") : null;
}

async function handleFeesRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- SET/UPDATE FEE STRUCTURE ----------------
  if (pathname === "/api/fee-structures" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { classId, term, session, amount } = await request.json();
    if (!classId || !term || !session || amount === undefined || amount === null) {
      return json({ error: "classId, term, session, and amount are required." }, 400);
    }
    if (isNaN(amount) || Number(amount) < 0) {
      return json({ error: "amount must be a non-negative number." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const existing = await env.DB
      .prepare("SELECT id FROM fee_structures WHERE class_id = ? AND term = ? AND session = ?")
      .bind(classId, term, session)
      .first();

    if (existing) {
      await env.DB.prepare("UPDATE fee_structures SET amount = ? WHERE id = ?").bind(Number(amount), existing.id).run();
    } else {
      await env.DB
        .prepare("INSERT INTO fee_structures (id, class_id, term, session, amount, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))")
        .bind(uuid(), classId, term, session, Number(amount))
        .run();
    }

    return json({ message: "Fee amount saved." });
  }

  // ---------------- LIST FEE STRUCTURES FOR A TERM ----------------
  if (pathname === "/api/fee-structures" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isFeeStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!term || !session) return json({ error: "term and session are required." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    const stmt = restriction
      ? env.DB.prepare(
          `SELECT c.id AS class_id, c.name AS class_name, fs.amount
           FROM classes c
           LEFT JOIN fee_structures fs ON fs.class_id = c.id AND fs.term = ? AND fs.session = ?
           WHERE c.level = ?
           ORDER BY c.sort_order`
        ).bind(term, session, restriction)
      : env.DB.prepare(
          `SELECT c.id AS class_id, c.name AS class_name, fs.amount
           FROM classes c
           LEFT JOIN fee_structures fs ON fs.class_id = c.id AND fs.term = ? AND fs.session = ?
           ORDER BY c.sort_order`
        ).bind(term, session);

    const { results } = await stmt.all();
    return json({ term, session, classes: results });
  }

  // ---------------- RECORD A PAYMENT (always live — never offline-queued) ----------------
  if (pathname === "/api/fees/payments" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isFeeStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { studentId, amount, type, term, session, notes } = await request.json();
    if (!studentId || !amount || !type || !term || !session) {
      return json({ error: "studentId, amount, type, term, and session are required." }, 400);
    }
    if (isNaN(amount) || Number(amount) <= 0) {
      return json({ error: "amount must be a positive number." }, 400);
    }

    const student = await env.DB.prepare("SELECT id, name, admission_no, class_id, level FROM students WHERE id = ?").bind(studentId).first();
    if (!student) return json({ error: "Student not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && student.level !== restriction) {
      return json({ error: "Not authorised for this student." }, 403);
    }

    const id = uuid();
    const recordedAt = new Date().toISOString();
    let receiptNo = null;
    try {
      // The next number is worked out inside the same statement, so two cashiers
      // saving at the same moment can never get the same receipt number.
      await env.DB
        .prepare(
          `INSERT INTO fee_transactions
             (id, student_id, student_name_snapshot, amount, type, term, session, recorded_by, recorded_at, notes, receipt_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(receipt_seq), 0) + 1 FROM fee_transactions))`
        )
        .bind(id, studentId, student.name, Number(amount), type, term, session, sessionCtx.id, recordedAt, notes || null)
        .run();
      const seqRow = await env.DB.prepare("SELECT receipt_seq FROM fee_transactions WHERE id = ?").bind(id).first();
      receiptNo = formatReceiptNo(seqRow && seqRow.receipt_seq);
    } catch (err) {
      // Safety net: if the receipt_seq column has not been added yet, still record the payment.
      if (!String(err && err.message || err).includes("receipt_seq")) throw err;
      await env.DB
        .prepare(
          `INSERT INTO fee_transactions
             (id, student_id, student_name_snapshot, amount, type, term, session, recorded_by, recorded_at, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(id, studentId, student.name, Number(amount), type, term, session, sessionCtx.id, recordedAt, notes || null)
        .run();
    }

    const structure = await env.DB
      .prepare("SELECT amount FROM fee_structures WHERE class_id = ? AND term = ? AND session = ?")
      .bind(student.class_id, term, session)
      .first();
    const feeAmount = structure ? structure.amount : 0;

    const paidRow = await env.DB
      .prepare("SELECT COALESCE(SUM(amount), 0) AS total FROM fee_transactions WHERE student_id = ? AND term = ? AND session = ?")
      .bind(studentId, term, session)
      .first();
    const totalPaid = paidRow.total;

    return json({
      message: "Payment recorded.",
      id,
      receipt: {
        receiptNo,
        studentName: student.name,
        admissionNo: student.admission_no,
        amount: Number(amount),
        type,
        term,
        session,
        notes: notes || null,
        recordedAt,
        feeAmount,
        totalPaid,
        balance: feeAmount - totalPaid
      }
    });
  }

  // ---------------- STUDENT FEE STATUS + HISTORY ----------------
  const studentFeeMatch = pathname.match(/^\/api\/fees\/student\/([^/]+)$/);
  if (studentFeeMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    const studentId = studentFeeMatch[1];
    const isSelf = sessionCtx && sessionCtx.type === "student" && sessionCtx.id === studentId;
    if (!isSelf && !isFeeStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!term || !session) return json({ error: "term and session are required." }, 400);

    const student = await env.DB.prepare("SELECT id, name, admission_no, class_id, level FROM students WHERE id = ?").bind(studentId).first();
    if (!student) return json({ error: "Student not found." }, 404);

    if (!isSelf) {
      const restriction = adminLevelRestriction(sessionCtx);
      if (restriction && student.level !== restriction) {
        return json({ error: "Not authorised for this student." }, 403);
      }
    }

    const structure = await env.DB
      .prepare("SELECT amount FROM fee_structures WHERE class_id = ? AND term = ? AND session = ?")
      .bind(student.class_id, term, session)
      .first();
    const feeAmount = structure ? structure.amount : 0;

    const paidRow = await env.DB
      .prepare("SELECT COALESCE(SUM(amount), 0) AS total FROM fee_transactions WHERE student_id = ? AND term = ? AND session = ?")
      .bind(studentId, term, session)
      .first();
    const totalPaid = paidRow.total;

    let transactions;
    try {
      const { results } = await env.DB
        .prepare(
          `SELECT id, amount, type, notes, recorded_at, receipt_seq
           FROM fee_transactions
           WHERE student_id = ? AND term = ? AND session = ?
           ORDER BY recorded_at DESC`
        )
        .bind(studentId, term, session)
        .all();
      transactions = results.map(t => ({ ...t, receiptNo: formatReceiptNo(t.receipt_seq) }));
    } catch (err) {
      // Safety net: column not added yet, so show the history without numbers
      if (!String(err && err.message || err).includes("receipt_seq")) throw err;
      const { results } = await env.DB
        .prepare(
          `SELECT id, amount, type, notes, recorded_at
           FROM fee_transactions
           WHERE student_id = ? AND term = ? AND session = ?
           ORDER BY recorded_at DESC`
        )
        .bind(studentId, term, session)
        .all();
      transactions = results;
    }

    return json({
      studentId,
      studentName: student.name,
      admissionNo: student.admission_no,
      feeAmount,
      totalPaid,
      balance: feeAmount - totalPaid,
      transactions
    });
  }

  // ---------------- CLASS FEE OVERVIEW ----------------
  const classFeeMatch = pathname.match(/^\/api\/fees\/class\/([^/]+)$/);
  if (classFeeMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isFeeStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = classFeeMatch[1];
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!term || !session) return json({ error: "term and session are required." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const structure = await env.DB
      .prepare("SELECT amount FROM fee_structures WHERE class_id = ? AND term = ? AND session = ?")
      .bind(classId, term, session)
      .first();
    const feeAmount = structure ? structure.amount : 0;

    const { results } = await env.DB
      .prepare(
        `SELECT s.id, s.name,
                COALESCE(SUM(ft.amount), 0) AS paid
         FROM students s
         LEFT JOIN fee_transactions ft
           ON ft.student_id = s.id AND ft.term = ? AND ft.session = ?
         WHERE s.class_id = ? AND s.status = 'active'
         GROUP BY s.id, s.name
         ORDER BY s.name COLLATE NOCASE`
      )
      .bind(term, session, classId)
      .all();

    const students = results.map(r => ({ id: r.id, name: r.name, paid: r.paid, balance: feeAmount - r.paid }));

    return json({ classId, term, session, feeAmount, students });
  }

  // ---------------- COLLECTION TOTALS (today / week / month / term) ----------------
  if (pathname === "/api/fees/totals" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isFeeStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!term || !session) return json({ error: "term and session are required." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    const levelJoin = restriction ? "JOIN students st ON st.id = ft.student_id AND st.level = ?" : "";
    const levelParams = restriction ? [restriction] : [];

    const now = new Date();
    const todayStr = now.toISOString().slice(0, 10);
    const weekStart = new Date(now);
    weekStart.setUTCDate(weekStart.getUTCDate() - 6);
    const weekStartStr = weekStart.toISOString().slice(0, 10);
    const monthStartStr = todayStr.slice(0, 7) + "-01";

    async function sumSince(sinceDate) {
      const row = await env.DB
        .prepare(
          `SELECT COALESCE(SUM(ft.amount), 0) AS total, COUNT(*) AS count
           FROM fee_transactions ft
           ${levelJoin}
           WHERE ft.term = ? AND ft.session = ? AND date(ft.recorded_at) >= date(?)`
        )
        .bind(...levelParams, term, session, sinceDate)
        .first();
      return { total: row.total, count: row.count };
    }

    const termRow = await env.DB
      .prepare(
        `SELECT COALESCE(SUM(ft.amount), 0) AS total, COUNT(*) AS count
         FROM fee_transactions ft
         ${levelJoin}
         WHERE ft.term = ? AND ft.session = ?`
      )
      .bind(...levelParams, term, session)
      .first();

    return json({
      term, session,
      today: await sumSince(todayStr),
      week: await sumSince(weekStartStr),
      month: await sumSince(monthStartStr),
      termTotal: { total: termRow.total, count: termRow.count }
    });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7G: Report Card routes (pulls together results, attendance,
// class rank, and fee status for one student/term)
// =====================================================================
/**
 * Routes:
 *   GET /api/report-card/:studentId?term=&session=
 *       (auth: teaching staff/admin, or the student viewing their own)
 *       Only APPROVED results are included — pendingSubjectCount tells
 *       you how many scores for that student still aren't approved yet.
 *   PUT /api/report-remarks/:studentId
 *       (auth: teaching staff for teacherRemark, admin for principalRemark)
 *       body: { term, session, teacherRemark?, principalRemark? }
 */
function suggestPrincipalRemark(average) {
  if (average === null || average === undefined) return "No results available yet for this term.";
  if (average >= 75) return "Excellent result. Keep up the outstanding performance.";
  if (average >= 65) return "Very good performance. Strive for the top.";
  if (average >= 55) return "Good result. There is still room for improvement.";
  if (average >= 45) return "Fair performance. More effort is required.";
  if (average >= 40) return "Below average. Needs to work much harder.";
  return "Poor performance. Serious improvement is required.";
}
async function handleReportCardRoutes(request, env, url) {
  const { pathname } = url;

  const match = pathname.match(/^\/api\/report-card\/([^/]+)$/);
  if (match && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    const studentId = match[1];
    if (!isTeachingStaff(sessionCtx) && !isOwnStudent(sessionCtx, studentId)) {
      return json({ error: "Not authorised." }, 403);
    }

    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!term || !session) return json({ error: "term and session are required." }, 400);

    const student = await env.DB
      .prepare(
        `SELECT s.id, s.name, s.admission_no, s.class_id, s.photo_key, s.dob, c.name AS class_name, c.level
         FROM students s JOIN classes c ON c.id = s.class_id
         WHERE s.id = ?`
      )
      .bind(studentId)
      .first();
    if (!student) return json({ error: "Student not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && isTeachingStaff(sessionCtx) && student.level !== restriction) {
      return json({ error: "Not authorised for this student." }, 403);
    }

    // ---- Subject scores (approved only) ----
    const { results: subjectRows } = await env.DB
      .prepare(
        `SELECT r.subject_id, sub.name AS subject_name, r.ca1, r.ca2, r.exam, r.grade
         FROM results r
         JOIN subjects sub ON sub.id = r.subject_id
         WHERE r.student_id = ? AND r.term = ? AND r.session = ? AND r.status = 'approved'
         ORDER BY sub.name`
      )
      .bind(studentId, term, session)
      .all();

    const subjects = subjectRows.map(r => ({
      subjectId: r.subject_id,
      subjectName: r.subject_name,
      ca1: r.ca1,
      ca2: r.ca2,
      exam: r.exam,
      total: (r.ca1 || 0) + (r.ca2 || 0) + (r.exam || 0),
      grade: r.grade
    }));

    const overallTotal = subjects.reduce((sum, s) => sum + s.total, 0);
    const average = subjects.length ? overallTotal / subjects.length : null;

    const pendingRow = await env.DB
      .prepare(
        `SELECT
           SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_count,
           SUM(CASE WHEN status = 'withheld' THEN 1 ELSE 0 END) AS withheld_count
         FROM results
         WHERE student_id = ? AND term = ? AND session = ? AND status != 'approved'`
      )
      .bind(studentId, term, session)
      .first();

    // ---- Class rank (among students with at least one approved result) ----
    const { results: classAverages } = await env.DB
      .prepare(
        `SELECT student_id, AVG(ca1 + ca2 + exam) AS avg_score
         FROM results
         WHERE class_id = ? AND term = ? AND session = ? AND status = 'approved'
         GROUP BY student_id
         ORDER BY avg_score DESC`
      )
      .bind(student.class_id, term, session)
      .all();

    const rankIndex = classAverages.findIndex(r => r.student_id === studentId);
    const position = rankIndex === -1 ? null : rankIndex + 1;
    const outOf = classAverages.length;

    // ---- Attendance for the term ----
    const attendance = await env.DB
      .prepare(
        `SELECT
           SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) AS present_count,
           SUM(CASE WHEN status = 'absent'  THEN 1 ELSE 0 END) AS absent_count,
           SUM(CASE WHEN status = 'late'    THEN 1 ELSE 0 END) AS late_count,
           SUM(CASE WHEN status = 'excused' THEN 1 ELSE 0 END) AS excused_count,
           COUNT(*) AS total_marked
         FROM attendance
         WHERE student_id = ? AND term = ? AND session = ?`
      )
      .bind(studentId, term, session)
      .first();

    // ---- Fee status for the term ----
    const feeStructure = await env.DB
      .prepare("SELECT amount FROM fee_structures WHERE class_id = ? AND term = ? AND session = ?")
      .bind(student.class_id, term, session)
      .first();
    const feeAmount = feeStructure ? feeStructure.amount : 0;
    const feePaidRow = await env.DB
      .prepare("SELECT COALESCE(SUM(amount), 0) AS total FROM fee_transactions WHERE student_id = ? AND term = ? AND session = ?")
      .bind(studentId, term, session)
      .first();

    // ---- Remarks ----
    const remarksRow = await env.DB
      .prepare("SELECT teacher_remark, principal_remark FROM report_remarks WHERE student_id = ? AND term = ? AND session = ?")
      .bind(studentId, term, session)
      .first();

    return json({
      student: {
        id: student.id,
        name: student.name,
        admissionNo: student.admission_no,
        className: student.class_name,
        level: student.level,
        dob: student.dob || null,
        photoUrl: student.photo_key || null
      },
      term,
      session,
      subjects,
      overallTotal,
      average,
      pendingSubjectCount: (pendingRow.pending_count || 0) + (pendingRow.withheld_count || 0),
      pendingCount: pendingRow.pending_count || 0,
      withheldCount: pendingRow.withheld_count || 0,
      position,
      outOf,
      attendance: {
        present: attendance.present_count || 0,
        absent: attendance.absent_count || 0,
        late: attendance.late_count || 0,
        excused: attendance.excused_count || 0,
        totalMarked: attendance.total_marked || 0
      },
      fee: {
        amount: feeAmount,
        paid: feePaidRow.total,
        balance: feeAmount - feePaidRow.total
      },
      teacherRemark: remarksRow ? remarksRow.teacher_remark : null,
      principalRemark: remarksRow ? remarksRow.principal_remark : null,
      suggestedPrincipalRemark: suggestPrincipalRemark(average)
    });
  }

  // ---------------- SAVE TEACHER/PRINCIPAL REMARK ----------------
  const remarkMatch = pathname.match(/^\/api\/report-remarks\/([^/]+)$/);
  if (remarkMatch && request.method === "PUT") {
    const sessionCtx = await getSession(request, env);
    const studentId = remarkMatch[1];
    const { term, session, teacherRemark, principalRemark } = await request.json();

    if (!term || !session) return json({ error: "term and session are required." }, 400);
    if (teacherRemark === undefined && principalRemark === undefined) {
      return json({ error: "Provide teacherRemark and/or principalRemark." }, 400);
    }
    if (teacherRemark !== undefined && !isTeachingStaff(sessionCtx)) {
      return json({ error: "Not authorised to set the teacher remark." }, 403);
    }
    if (principalRemark !== undefined && !isAdminSession(sessionCtx)) {
      return json({ error: "Not authorised to set the principal remark." }, 403);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const stu = await env.DB.prepare("SELECT level FROM students WHERE id = ?").bind(studentId).first();
      if (!stu || stu.level !== restriction) return json({ error: "Not authorised for this student." }, 403);
    }

    const existing = await env.DB
      .prepare("SELECT id, teacher_remark, principal_remark FROM report_remarks WHERE student_id = ? AND term = ? AND session = ?")
      .bind(studentId, term, session)
      .first();

    const nextTeacherRemark = teacherRemark !== undefined ? teacherRemark : (existing ? existing.teacher_remark : null);
    const nextPrincipalRemark = principalRemark !== undefined ? principalRemark : (existing ? existing.principal_remark : null);

    if (existing) {
      await env.DB
        .prepare("UPDATE report_remarks SET teacher_remark = ?, principal_remark = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(nextTeacherRemark, nextPrincipalRemark, existing.id)
        .run();
    } else {
      await env.DB
        .prepare(
          `INSERT INTO report_remarks (id, student_id, term, session, teacher_remark, principal_remark, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
        )
        .bind(uuid(), studentId, term, session, nextTeacherRemark, nextPrincipalRemark)
        .run();
    }

    return json({ message: "Remark saved." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7H: CBT routes (Computer-Based Testing — MCQ/True-False,
// created by teachers/admins, taken by students, auto-graded instantly)
// =====================================================================
/**
 * Routes (teaching staff = teacher or admin):
 *   POST   /api/cbt/tests                       (teaching staff) create a test (starts as 'draft')
 *   GET    /api/cbt/tests?classId=&term=&session=  (teaching staff) list tests for a class
 *   PATCH  /api/cbt/tests/:id                    (teaching staff) update title/duration/status
 *   DELETE /api/cbt/tests/:id                    (teaching staff) delete test + its questions/submissions
 *   POST   /api/cbt/tests/:id/questions          (teaching staff) add a question
 *   GET    /api/cbt/tests/:id/questions          (teaching staff) list questions (includes correct answers)
 *   DELETE /api/cbt/tests/:id/questions/:qId     (teaching staff) remove a question
 *   GET    /api/cbt/tests/:id/results            (teaching staff) list of student scores
 *
 * Routes (student — sees only their own class's published tests):
 *   GET  /api/cbt/available                      (student) published tests for their class, with submitted/score if taken
 *   GET  /api/cbt/tests/:id/take                 (student) questions WITHOUT correct answers, to attempt
 *   POST /api/cbt/tests/:id/submit               (student) { answers: {questionId: 'A'|'B'|'C'|'D'|'true'|'false'} }
 */
async function handleCbtRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- CREATE TEST ----------------
  if (pathname === "/api/cbt/tests" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised. Only admins can create and publish tests." }, 403);

    const { title, classId, subjectId, term, session, durationMinutes } = await request.json();
    if (!title || !classId || !subjectId || !term || !session || !durationMinutes) {
      return json({ error: "title, classId, subjectId, term, session, and durationMinutes are required." }, 400);
    }
    if (isNaN(durationMinutes) || Number(durationMinutes) <= 0) {
      return json({ error: "durationMinutes must be a positive number." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO cbt_tests (id, title, class_id, subject_id, term, session, duration_minutes, status, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, datetime('now'))`
      )
      .bind(id, title, classId, subjectId, term, session, Number(durationMinutes), sessionCtx.id)
      .run();

    return json({ message: "Test created as a draft. Add questions, then publish it.", id });
  }

  // ---------------- LIST TESTS FOR A CLASS ----------------
  if (pathname === "/api/cbt/tests" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = url.searchParams.get("classId");
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!classId || !term || !session) return json({ error: "classId, term, and session are required." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT t.id, t.title, t.duration_minutes, t.status, t.created_at, t.subject_id, sub.name AS subject_name,
                (SELECT COUNT(*) FROM cbt_questions q WHERE q.test_id = t.id) AS question_count,
                (SELECT COUNT(*) FROM cbt_submissions s WHERE s.test_id = t.id) AS submission_count
         FROM cbt_tests t
         JOIN subjects sub ON sub.id = t.subject_id
         WHERE t.class_id = ? AND t.term = ? AND t.session = ?
         ORDER BY t.created_at DESC`
      )
      .bind(classId, term, session)
      .all();

    return json({ tests: results });
  }

  // ---------------- UPDATE TEST (title/duration/status) ----------------
  const testMatch = pathname.match(/^\/api\/cbt\/tests\/([^/]+)$/);
  if (testMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised. Only admins can manage tests." }, 403);

    const testId = testMatch[1];
    const { title, durationMinutes, status } = await request.json();

    const test = await env.DB.prepare("SELECT id, class_id FROM cbt_tests WHERE id = ?").bind(testId).first();
    if (!test) return json({ error: "Test not found." }, 404);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(test.class_id).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this test." }, 403);
    }

    if (status !== undefined) {
      if (!["draft", "published"].includes(status)) return json({ error: "status must be 'draft' or 'published'." }, 400);
      if (status === "published") {
        const qCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM cbt_questions WHERE test_id = ?").bind(testId).first();
        if (qCount.count === 0) return json({ error: "Add at least one question before publishing." }, 400);
      }
      await env.DB.prepare("UPDATE cbt_tests SET status = ? WHERE id = ?").bind(status, testId).run();
    }
    if (title !== undefined) {
      await env.DB.prepare("UPDATE cbt_tests SET title = ? WHERE id = ?").bind(title, testId).run();
    }
    if (durationMinutes !== undefined) {
      await env.DB.prepare("UPDATE cbt_tests SET duration_minutes = ? WHERE id = ?").bind(Number(durationMinutes), testId).run();
    }

    return json({ message: "Test updated." });
  }

  // ---------------- DELETE TEST ----------------
  if (testMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised. Only admins can delete tests." }, 403);

    const testId = testMatch[1];
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const test = await env.DB.prepare("SELECT class_id FROM cbt_tests WHERE id = ?").bind(testId).first();
      if (test) {
        const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(test.class_id).first();
        if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this test." }, 403);
      }
    }

    await env.DB.prepare("DELETE FROM cbt_submissions WHERE test_id = ?").bind(testId).run();
    await env.DB.prepare("DELETE FROM cbt_questions WHERE test_id = ?").bind(testId).run();
    await env.DB.prepare("DELETE FROM cbt_tests WHERE id = ?").bind(testId).run();

    return json({ message: "Test deleted." });
  }

  // ---------------- ADD A QUESTION ----------------
  const questionsMatch = pathname.match(/^\/api\/cbt\/tests\/([^/]+)\/questions$/);
  if (questionsMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised. Only admins manage test questions directly." }, 403);

    const testId = questionsMatch[1];
    const test = await env.DB.prepare("SELECT id, status, class_id FROM cbt_tests WHERE id = ?").bind(testId).first();
    if (!test) return json({ error: "Test not found." }, 404);
    if (test.status === "published") return json({ error: "Unpublish the test before editing its questions." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(test.class_id).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this test." }, 403);
    }

    const { questionText, type, optionA, optionB, optionC, optionD, correctOption, points, saveToBank } = await request.json();
    if (!questionText || !type || !correctOption) {
      return json({ error: "questionText, type, and correctOption are required." }, 400);
    }
    if (!["mcq", "true_false"].includes(type)) return json({ error: "type must be 'mcq' or 'true_false'." }, 400);
    if (type === "mcq" && (!optionA || !optionB)) {
      return json({ error: "MCQ questions need at least optionA and optionB." }, 400);
    }
    if (type === "true_false" && !["true", "false"].includes(correctOption)) {
      return json({ error: "For true_false questions, correctOption must be 'true' or 'false'." }, 400);
    }
    if (type === "mcq" && !["A", "B", "C", "D"].includes(correctOption)) {
      return json({ error: "For mcq questions, correctOption must be 'A', 'B', 'C', or 'D'." }, 400);
    }

    const countRow = await env.DB.prepare("SELECT COUNT(*) AS count FROM cbt_questions WHERE test_id = ?").bind(testId).first();

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO cbt_questions (id, test_id, question_text, type, option_a, option_b, option_c, option_d, correct_option, points, sort_order)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(id, testId, questionText, type, optionA || null, optionB || null, optionC || null, optionD || null, correctOption, points || 1, countRow.count)
      .run();

    if (saveToBank) {
      const testInfo = await env.DB.prepare("SELECT class_id, subject_id, term FROM cbt_tests WHERE id = ?").bind(testId).first();
      await env.DB
        .prepare(
          `INSERT INTO cbt_question_bank (id, class_id, subject_id, term, question_text, type, option_a, option_b, option_c, option_d, correct_option, points, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
        )
        .bind(uuid(), testInfo.class_id, testInfo.subject_id, testInfo.term, questionText, type, optionA || null, optionB || null, optionC || null, optionD || null, correctOption, points || 1, sessionCtx.id)
        .run();
    }

    return json({ message: "Question added.", id });
  }

  // ---------------- LIST QUESTIONS (with correct answers, for editing) ----------------
  if (questionsMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const testId = questionsMatch[1];
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const test = await env.DB.prepare("SELECT class_id FROM cbt_tests WHERE id = ?").bind(testId).first();
      if (test) {
        const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(test.class_id).first();
        if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this test." }, 403);
      }
    }

    const { results } = await env.DB
      .prepare("SELECT * FROM cbt_questions WHERE test_id = ? ORDER BY sort_order")
      .bind(testId)
      .all();

    return json({ questions: results });
  }

  // ---------------- DELETE A QUESTION ----------------
  const questionDeleteMatch = pathname.match(/^\/api\/cbt\/tests\/([^/]+)\/questions\/([^/]+)$/);
  if (questionDeleteMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const [, testId, questionId] = questionDeleteMatch;
    const test = await env.DB.prepare("SELECT status, class_id FROM cbt_tests WHERE id = ?").bind(testId).first();
    if (test && test.status === "published") return json({ error: "Unpublish the test before editing its questions." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction && test) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(test.class_id).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this test." }, 403);
    }

    await env.DB.prepare("DELETE FROM cbt_questions WHERE id = ? AND test_id = ?").bind(questionId, testId).run();
    return json({ message: "Question removed." });
  }

  // ---------------- QUESTION BANK: ADD ----------------
  if (pathname === "/api/cbt/question-bank" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { classId, subjectId, term, questionText, type, optionA, optionB, optionC, optionD, correctOption, points } = await request.json();
    if (!classId || !subjectId || !term || !questionText || !type || !correctOption) {
      return json({ error: "classId, subjectId, term, questionText, type, and correctOption are required." }, 400);
    }
    if (!["mcq", "true_false"].includes(type)) return json({ error: "type must be 'mcq' or 'true_false'." }, 400);
    if (type === "mcq" && (!optionA || !optionB)) {
      return json({ error: "MCQ questions need at least optionA and optionB." }, 400);
    }
    if (type === "true_false" && !["true", "false"].includes(correctOption)) {
      return json({ error: "For true_false questions, correctOption must be 'true' or 'false'." }, 400);
    }
    if (type === "mcq" && !["A", "B", "C", "D"].includes(correctOption)) {
      return json({ error: "For mcq questions, correctOption must be 'A', 'B', 'C', or 'D'." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO cbt_question_bank (id, class_id, subject_id, term, question_text, type, option_a, option_b, option_c, option_d, correct_option, points, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(id, classId, subjectId, term, questionText, type, optionA || null, optionB || null, optionC || null, optionD || null, correctOption, points || 1, sessionCtx.id)
      .run();

    return json({ message: "Added to question bank.", id });
  }

  // ---------------- QUESTION BANK: LIST ----------------
  if (pathname === "/api/cbt/question-bank" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = url.searchParams.get("classId");
    const subjectId = url.searchParams.get("subjectId");
    const term = url.searchParams.get("term");
    if (!classId || !subjectId || !term) return json({ error: "classId, subjectId, and term are required." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT * FROM cbt_question_bank
         WHERE class_id = ? AND subject_id = ? AND term = ?
         ORDER BY created_at DESC`
      )
      .bind(classId, subjectId, term)
      .all();

    return json({ questions: results });
  }

  // ---------------- QUESTION BANK: DELETE ----------------
  const bankDeleteMatch = pathname.match(/^\/api\/cbt\/question-bank\/([^/]+)$/);
  if (bankDeleteMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const bq = await env.DB.prepare("SELECT class_id FROM cbt_question_bank WHERE id = ?").bind(bankDeleteMatch[1]).first();
      if (bq) {
        const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(bq.class_id).first();
        if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this question." }, 403);
      }
    }

    await env.DB.prepare("DELETE FROM cbt_question_bank WHERE id = ?").bind(bankDeleteMatch[1]).run();
    return json({ message: "Removed from question bank." });
  }

  // ---------------- ADD QUESTIONS TO A TEST FROM THE BANK ----------------
  const fromBankMatch = pathname.match(/^\/api\/cbt\/tests\/([^/]+)\/questions\/from-bank$/);
  if (fromBankMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised. Only admins manage test questions directly." }, 403);

    const testId = fromBankMatch[1];
    const test = await env.DB.prepare("SELECT id, status, class_id FROM cbt_tests WHERE id = ?").bind(testId).first();
    if (!test) return json({ error: "Test not found." }, 404);
    if (test.status === "published") return json({ error: "Unpublish the test before editing its questions." }, 400);

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(test.class_id).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this test." }, 403);
    }

    const { questionBankIds } = await request.json();
    if (!Array.isArray(questionBankIds) || !questionBankIds.length) {
      return json({ error: "questionBankIds must be a non-empty array." }, 400);
    }

    const countRow = await env.DB.prepare("SELECT COUNT(*) AS count FROM cbt_questions WHERE test_id = ?").bind(testId).first();
    let nextOrder = countRow.count;
    let added = 0;

    for (const bankId of questionBankIds) {
      const bq = await env.DB.prepare("SELECT * FROM cbt_question_bank WHERE id = ?").bind(bankId).first();
      if (!bq) continue;

      await env.DB
        .prepare(
          `INSERT INTO cbt_questions (id, test_id, question_text, type, option_a, option_b, option_c, option_d, correct_option, points, sort_order)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(uuid(), testId, bq.question_text, bq.type, bq.option_a, bq.option_b, bq.option_c, bq.option_d, bq.correct_option, bq.points, nextOrder)
        .run();

      nextOrder++;
      added++;
    }

    return json({ message: added + " question(s) added from the bank.", added });
  }

  // ---------------- RESULTS FOR A TEST (teaching staff) ----------------
  const resultsMatch = pathname.match(/^\/api\/cbt\/tests\/([^/]+)\/results$/);
  if (resultsMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const testId = resultsMatch[1];
    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const test = await env.DB.prepare("SELECT class_id FROM cbt_tests WHERE id = ?").bind(testId).first();
      if (test) {
        const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(test.class_id).first();
        if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this test." }, 403);
      }
    }

    const { results } = await env.DB
      .prepare(
        `SELECT s.id, st.name AS student_name, st.admission_no, s.score, s.total_points, s.submitted_at
         FROM cbt_submissions s
         JOIN students st ON st.id = s.student_id
         WHERE s.test_id = ?
         ORDER BY s.score DESC`
      )
      .bind(testId)
      .all();

    return json({ results });
  }

  // ---------------- STUDENT: AVAILABLE TESTS ----------------
  if (pathname === "/api/cbt/available" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx || sessionCtx.type !== "student") return json({ error: "Not authorised." }, 403);

    const classId = sessionCtx.record.class_id;
    const { results } = await env.DB
      .prepare(
        `SELECT t.id, t.title, t.duration_minutes, t.term, t.session, sub.name AS subject_name,
                (SELECT COUNT(*) FROM cbt_questions q WHERE q.test_id = t.id) AS question_count,
                sub2.score, sub2.total_points
         FROM cbt_tests t
         JOIN subjects sub ON sub.id = t.subject_id
         LEFT JOIN cbt_submissions sub2 ON sub2.test_id = t.id AND sub2.student_id = ?
         WHERE t.class_id = ? AND (t.status = 'published' OR sub2.score IS NOT NULL)
         ORDER BY t.created_at DESC`
      )
      .bind(sessionCtx.id, classId)
      .all();

    return json({
      tests: results.map(r => ({
        id: r.id, title: r.title, subjectName: r.subject_name, durationMinutes: r.duration_minutes,
        term: r.term, session: r.session, questionCount: r.question_count,
        submitted: r.score !== null, score: r.score, totalPoints: r.total_points
      }))
    });
  }

  // ---------------- STUDENT: TAKE A TEST ----------------
  const takeMatch = pathname.match(/^\/api\/cbt\/tests\/([^/]+)\/take$/);
  if (takeMatch && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx || sessionCtx.type !== "student") return json({ error: "Not authorised." }, 403);

    const testId = takeMatch[1];
    const test = await env.DB.prepare("SELECT * FROM cbt_tests WHERE id = ? AND status = 'published'").bind(testId).first();
    if (!test) return json({ error: "Test not found or not available." }, 404);
    if (test.class_id !== sessionCtx.record.class_id) return json({ error: "This test is not for your class." }, 403);

    const existing = await env.DB
      .prepare("SELECT score, total_points FROM cbt_submissions WHERE test_id = ? AND student_id = ?")
      .bind(testId, sessionCtx.id)
      .first();
    if (existing) return json({ error: "You have already submitted this test.", alreadySubmitted: true, score: existing.score, totalPoints: existing.total_points }, 409);

    const { results: questions } = await env.DB
      .prepare("SELECT id, question_text, type, option_a, option_b, option_c, option_d, points FROM cbt_questions WHERE test_id = ? ORDER BY sort_order")
      .bind(testId)
      .all();

    return json({
      test: { id: test.id, title: test.title, durationMinutes: test.duration_minutes },
      questions
    });
  }

  // ---------------- STUDENT: SUBMIT A TEST ----------------
  const submitMatch = pathname.match(/^\/api\/cbt\/tests\/([^/]+)\/submit$/);
  if (submitMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx || sessionCtx.type !== "student") return json({ error: "Not authorised." }, 403);

    const testId = submitMatch[1];
    const test = await env.DB.prepare("SELECT * FROM cbt_tests WHERE id = ? AND status = 'published'").bind(testId).first();
    if (!test) return json({ error: "Test not found or not available." }, 404);
    if (test.class_id !== sessionCtx.record.class_id) return json({ error: "This test is not for your class." }, 403);

    const existing = await env.DB
      .prepare("SELECT id FROM cbt_submissions WHERE test_id = ? AND student_id = ?")
      .bind(testId, sessionCtx.id)
      .first();
    if (existing) return json({ error: "You have already submitted this test." }, 409);

    const { answers } = await request.json();
    if (!answers || typeof answers !== "object") return json({ error: "answers is required." }, 400);

    const { results: questions } = await env.DB
      .prepare("SELECT id, correct_option, points FROM cbt_questions WHERE test_id = ?")
      .bind(testId)
      .all();

    let score = 0;
    let totalPoints = 0;
    for (const q of questions) {
      totalPoints += q.points;
      if (answers[q.id] !== undefined && String(answers[q.id]).toUpperCase() === String(q.correct_option).toUpperCase()) {
        score += q.points;
      }
    }

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO cbt_submissions (id, test_id, student_id, answers_json, score, total_points, submitted_at)
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(id, testId, sessionCtx.id, JSON.stringify(answers), score, totalPoints)
      .run();

    return json({ message: "Test submitted.", score, totalPoints });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7I: Announcements routes (admin posts, staff/students see a
// feed filtered to what's relevant to them)
// =====================================================================
/**
 * Routes:
 *   POST   /api/announcements        (auth: general_admin) { title, body, audience }
 *   GET    /api/announcements        (auth: any logged-in) personalised feed
 *   GET    /api/announcements/all    (auth: admin) full unfiltered list, for management
 *   GET    /api/public/announcements (public) recent audience='all' announcements, for the landing-page ticker
 *   DELETE /api/announcements/:id    (auth: general_admin)
 *
 * `audience` is one of: 'all', 'staff', 'teachers', 'students',
 * 'primary', 'secondary', or 'class_<classId>'.
 */
function announcementMatchesSession(audience, sessionCtx) {
  if (audience === "all") return true;

  if (sessionCtx.type === "staff") {
    if (isAdminSession(sessionCtx)) return true; // admins see everything
    if (audience === "staff") return true;
    if (audience === "teachers" && sessionCtx.role === "teacher") return true;
    if ((audience === "primary" || audience === "secondary") && sessionCtx.level === audience) return true;
    return false; // class_<id> announcements aren't shown to staff in this feed
  }

  if (sessionCtx.type === "student") {
    if (audience === "students") return true;
    if ((audience === "primary" || audience === "secondary") && sessionCtx.record.level === audience) return true;
    if (audience === "class_" + sessionCtx.record.class_id) return true;
    return false;
  }

  return false;
}

async function handleAnnouncementRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- POST AN ANNOUNCEMENT ----------------
  if (pathname === "/api/announcements" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { title, body, audience } = await request.json();
    if (!title || !body || !audience) {
      return json({ error: "title, body, and audience are required." }, 400);
    }
    const validPrefixes = ["all", "staff", "teachers", "students", "primary", "secondary"];
    if (!validPrefixes.includes(audience) && !audience.startsWith("class_")) {
      return json({ error: "Invalid audience." }, 400);
    }

    const id = uuid();
    await env.DB
      .prepare("INSERT INTO announcements (id, title, body, audience, created_by, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))")
      .bind(id, title, body, audience, sessionCtx.id)
      .run();

    return json({ message: "Posted.", id });
  }

  // ---------------- PERSONALISED FEED ----------------
  if (pathname === "/api/announcements" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!sessionCtx) return json({ error: "Not authenticated." }, 401);

    const { results } = await env.DB
      .prepare("SELECT id, title, body, audience, created_at FROM announcements ORDER BY created_at DESC LIMIT 100")
      .all();

    const feed = results.filter(a => announcementMatchesSession(a.audience, sessionCtx));
    return json({ announcements: feed });
  }

  // ---------------- PUBLIC: LANDING PAGE TICKER FEED ----------------
  if (pathname === "/api/public/announcements" && request.method === "GET") {
    const { results } = await env.DB
      .prepare("SELECT id, title, body, created_at FROM announcements WHERE audience = 'all' ORDER BY created_at DESC LIMIT 20")
      .all();
    return json({ announcements: results });
  }

  // ---------------- FULL LIST (admin management) ----------------
  if (pathname === "/api/announcements/all" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { results } = await env.DB
      .prepare(
        `SELECT a.id, a.title, a.body, a.audience, a.created_at, u.name AS created_by_name
         FROM announcements a
         LEFT JOIN users u ON u.id = a.created_by
         ORDER BY a.created_at DESC LIMIT 200`
      )
      .all();

    const restriction = adminLevelRestriction(sessionCtx);
    if (!restriction) return json({ announcements: results });

    const { results: classRows } = await env.DB.prepare("SELECT id, level FROM classes").all();
    const classLevelMap = Object.fromEntries(classRows.map(c => [c.id, c.level]));

    const filtered = results.filter(a => {
      if (a.audience === restriction) return true;
      if (a.audience.startsWith("class_")) {
        return classLevelMap[a.audience.slice("class_".length)] === restriction;
      }
      return false;
    });

    return json({ announcements: filtered });
  }

  // ---------------- DELETE ----------------
  const deleteMatch = pathname.match(/^\/api\/announcements\/([^/]+)$/);
  if (deleteMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    await env.DB.prepare("DELETE FROM announcements WHERE id = ?").bind(deleteMatch[1]).run();
    return json({ message: "Deleted." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7B2: Site content routes (public About Us + Leadership Directory)
// =====================================================================
/**
 * FIS Itobe Portal — Worker API (Site Content: About Us + Leadership)
 *
 * Routes:
 *   GET   /api/public/about                    (public) current About Us text
 *   PUT   /api/settings/about                   (auth: general_admin) { value }
 *   GET   /api/public/contact                   (public) current contact info (address, phones, email)
 *   PUT   /api/settings/contact                  (auth: general_admin) { address, phones, email }
 *   GET   /api/public/leadership                (public) leadership list, ordered
 *   GET   /api/leadership                       (auth: general_admin) leadership list (admin management)
 *   POST  /api/leadership                       (auth: general_admin) { name, title, phone, bio, sortOrder }
 *   PATCH /api/leadership/:id                   (auth: general_admin) partial update
 *   DELETE /api/leadership/:id                  (auth: general_admin)
 */
async function handleSiteContentRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- PUBLIC: ABOUT US ----------------
  if (pathname === "/api/public/about" && request.method === "GET") {
    const row = await env.DB.prepare("SELECT value FROM portal_settings WHERE key = 'about_us'").first();
    return json({ value: row ? row.value : null });
  }

  // ---------------- ADMIN: SAVE ABOUT US ----------------
  if (pathname === "/api/settings/about" && request.method === "PUT") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { value } = await request.json();
    if (typeof value !== "string" || !value.trim()) {
      return json({ error: "value is required." }, 400);
    }

    await env.DB
      .prepare(
        `INSERT INTO portal_settings (key, value) VALUES ('about_us', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`
      )
      .bind(value.trim())
      .run();

    return json({ message: "About Us updated." });
  }

  // ---------------- PUBLIC: CONTACT INFO ----------------
  // Single source of truth for phones/email/address shown in the portal's
  // own footer and — via this same public, unauthenticated endpoint — on
  // any other site (e.g. the separate public landing page/builder) that
  // wants to pull the school's contact details live instead of hardcoding
  // them, so they only ever need to be updated in one place.
  if (pathname === "/api/public/contact" && request.method === "GET") {
    const row = await env.DB.prepare("SELECT value FROM portal_settings WHERE key = 'contact_info'").first();
    const fallback = { address: null, phones: [], email: null };
    if (!row) return json(fallback);
    try {
      return json(JSON.parse(row.value));
    } catch {
      return json(fallback);
    }
  }

  // ---------------- ADMIN: SAVE CONTACT INFO ----------------
  if (pathname === "/api/settings/contact" && request.method === "PUT") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const body = await request.json();
    const address = typeof body.address === "string" ? body.address.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const phones = Array.isArray(body.phones)
      ? body.phones.map(p => String(p).trim()).filter(Boolean)
      : String(body.phones || "").split(",").map(p => p.trim()).filter(Boolean);

    if (!address && !email && !phones.length) {
      return json({ error: "Provide at least an address, phone number, or email." }, 400);
    }

    const value = JSON.stringify({ address, phones, email });

    await env.DB
      .prepare(
        `INSERT INTO portal_settings (key, value) VALUES ('contact_info', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`
      )
      .bind(value)
      .run();

    return json({ message: "Contact info updated.", address, phones, email });
  }

  // ---------------- PUBLIC: LEADERSHIP LIST ----------------
  if (pathname === "/api/public/leadership" && request.method === "GET") {
    const { results } = await env.DB
      .prepare("SELECT id, name, title, phone, bio FROM leadership ORDER BY sort_order ASC, name ASC")
      .all();
    return json({ leadership: results });
  }

  // ---------------- ADMIN: LEADERSHIP LIST (management) ----------------
  if (pathname === "/api/leadership" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { results } = await env.DB
      .prepare("SELECT id, name, title, phone, bio, sort_order FROM leadership ORDER BY sort_order ASC, name ASC")
      .all();
    return json({ leadership: results });
  }

  // ---------------- ADMIN: ADD LEADER ----------------
  if (pathname === "/api/leadership" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { name, title, phone, bio, sortOrder } = await request.json();
    if (!name || !title) return json({ error: "name and title are required." }, 400);

    const id = uuid();
    await env.DB
      .prepare(
        "INSERT INTO leadership (id, name, title, phone, bio, sort_order) VALUES (?, ?, ?, ?, ?, ?)"
      )
      .bind(id, name, title, phone || null, bio || null, Number.isFinite(sortOrder) ? sortOrder : 0)
      .run();

    return json({ message: "Leader added.", id });
  }

  // ---------------- ADMIN: UPDATE LEADER ----------------
  const updateMatch = pathname.match(/^\/api\/leadership\/([^/]+)$/);
  if (updateMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const existing = await env.DB.prepare("SELECT * FROM leadership WHERE id = ?").bind(updateMatch[1]).first();
    if (!existing) return json({ error: "Leader not found." }, 404);

    const body = await request.json();
    const name = body.name !== undefined ? body.name : existing.name;
    const title = body.title !== undefined ? body.title : existing.title;
    const phone = body.phone !== undefined ? body.phone : existing.phone;
    const bio = body.bio !== undefined ? body.bio : existing.bio;
    const sortOrder = body.sortOrder !== undefined ? body.sortOrder : existing.sort_order;

    await env.DB
      .prepare("UPDATE leadership SET name = ?, title = ?, phone = ?, bio = ?, sort_order = ? WHERE id = ?")
      .bind(name, title, phone, bio, sortOrder, updateMatch[1])
      .run();

    return json({ message: "Leader updated." });
  }

  // ---------------- ADMIN: DELETE LEADER ----------------
  if (updateMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    await env.DB.prepare("DELETE FROM leadership WHERE id = ?").bind(updateMatch[1]).run();
    return json({ message: "Leader removed." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7B3: Gallery routes (public video/photo/text tiles)
// =====================================================================
/**
 * FIS Itobe Portal — Worker API (School Gallery)
 *
 * One-time D1 migration (run via wrangler or the D1 console):
 *
 * CREATE TABLE gallery (
 *   id TEXT PRIMARY KEY,
 *   item_type TEXT NOT NULL DEFAULT 'video',  -- 'video' | 'photo' | 'text'
 *   title TEXT,
 *   caption TEXT,
 *   video_url TEXT,
 *   photo_url TEXT,
 *   text_body TEXT,
 *   sort_order INTEGER NOT NULL DEFAULT 0,
 *   created_at TEXT NOT NULL
 * );
 *
 * Routes:
 *   GET    /api/public/gallery   (public) every item, tile-ordered
 *   GET    /api/gallery          (auth: general_admin) same list, for management
 *   POST   /api/gallery          (auth: general_admin)
 *          { itemType: 'video'|'photo'|'text', title?, caption?, videoUrl?, photoUrl?, textBody?, sortOrder? }
 *   DELETE /api/gallery/:id      (auth: general_admin)
 */
function galleryRowToJson(row) {
  return {
    id: row.id,
    itemType: row.item_type,
    title: row.title,
    caption: row.caption,
    video_url: row.video_url,
    photo_url: row.photo_url,
    text_body: row.text_body,
    sort_order: row.sort_order,
    created_at: row.created_at
  };
}

async function handleGalleryRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- PUBLIC: GALLERY LIST ----------------
  if (pathname === "/api/public/gallery" && request.method === "GET") {
    try {
      const { results } = await env.DB
        .prepare("SELECT * FROM gallery ORDER BY sort_order ASC, created_at DESC")
        .all();
      return json({ items: results.map(galleryRowToJson) });
    } catch (err) {
      return json({ error: "gallery table not found — run the migration first.", detail: String((err && err.message) || err) }, 500);
    }
  }

  // ---------------- ADMIN: GALLERY LIST (management) ----------------
  if (pathname === "/api/gallery" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    try {
      const { results } = await env.DB
        .prepare("SELECT * FROM gallery ORDER BY sort_order ASC, created_at DESC")
        .all();
      return json({ items: results.map(galleryRowToJson) });
    } catch (err) {
      return json({ error: "gallery table not found — run the migration first.", detail: String((err && err.message) || err) }, 500);
    }
  }

  // ---------------- ADMIN: ADD GALLERY ITEM ----------------
  if (pathname === "/api/gallery" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { itemType, title, caption, videoUrl, photoUrl, textBody, sortOrder } = await request.json();
    const type = ["video", "photo", "text"].includes(itemType) ? itemType : "video";

    if (type === "video" && !videoUrl) return json({ error: "videoUrl is required for a video item." }, 400);
    if (type === "photo" && !photoUrl) return json({ error: "photoUrl is required for a photo item." }, 400);
    if (type === "text" && (!textBody || !textBody.trim())) return json({ error: "textBody is required for a text item." }, 400);

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO gallery (id, item_type, title, caption, video_url, photo_url, text_body, sort_order, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(
        id, type, title || null, caption || null,
        type === "video" ? videoUrl : null,
        type === "photo" ? photoUrl : null,
        type === "text" ? textBody.trim() : null,
        Number.isFinite(sortOrder) ? sortOrder : 0
      )
      .run();

    return json({ message: "Gallery item saved.", id });
  }

  // ---------------- ADMIN: DELETE GALLERY ITEM ----------------
  const galDeleteMatch = pathname.match(/^\/api\/gallery\/([^/]+)$/);
  if (galDeleteMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    await env.DB.prepare("DELETE FROM gallery WHERE id = ?").bind(galDeleteMatch[1]).run();
    return json({ message: "Gallery item removed." });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7B4: Birthday routes (auto-detected list + SMS + public wishes)
// =====================================================================
/**
 * FIS Itobe Portal — Worker API (Birthdays)
 *
 * Two independent pieces:
 *  - Auto-detected list, from students.dob / users.dob (month-day match
 *    against today, year ignored) — used by the admin panel to see who
 *    is celebrating today and to send the birthday SMS.
 *  - Admin-authored public "wishes" (a photo + a message posted for a
 *    specific person on the day of), shown on the public landing page.
 *    These are independent of the auto-detected list on purpose — an
 *    admin picks who to post for and writes the message each time.
 *
 * One-time D1 migrations:
 *
 * ALTER TABLE users ADD COLUMN dob TEXT;   -- staff date of birth, optional
 *
 * CREATE TABLE birthday_wishes (
 *   id TEXT PRIMARY KEY,
 *   person_type TEXT NOT NULL,   -- 'student' | 'staff'
 *   person_id TEXT,
 *   name TEXT NOT NULL,
 *   photo_url TEXT,
 *   message TEXT NOT NULL,
 *   wish_date TEXT NOT NULL,     -- YYYY-MM-DD, set server-side to today
 *   created_at TEXT NOT NULL
 * );
 *
 * Automatic birthday SMS (one more migration):
 *
 * ALTER TABLE birthday_wishes ADD COLUMN sms_status TEXT;   -- 'sent' | 'failed' | 'skipped'
 *
 * Staff are texted automatically when their wish is created. Students' guardians
 * are texted only when the General Admin approves the wish (optional tick box).
 *
 * Automatic wishes (run once more if upgrading from the earlier version):
 *
 * ALTER TABLE birthday_wishes ADD COLUMN status TEXT NOT NULL DEFAULT 'approved';
 * ALTER TABLE birthday_wishes ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
 * CREATE UNIQUE INDEX idx_bw_person_day ON birthday_wishes(person_type, person_id, wish_date) WHERE person_id IS NOT NULL;
 *
 * Staff AND student birthdays are turned into homepage wishes automatically.
 * Staff are texted automatically. A student's guardian SMS waits for the
 * General Admin (sms_status 'pending' -> 'sent' | 'declined' | 'failed').
 * If upgrading from the approval-first version, run once:
 *   UPDATE birthday_wishes SET status = 'approved', sms_status = 'pending' WHERE status = 'pending';
 *
 * Routes:
 *   PATCH /api/birthday-wishes/:id  (auth: general_admin) { message?, smsAction?: 'send'|'skip', status?: 'rejected' }
 *   GET  /api/birthdays/today       (auth: general_admin) auto-detected list for today
 *   POST /api/sms/notify-birthdays  (auth: general_admin) { message } — texts today's list
 *   GET  /api/public/birthdays      (public) today's posted wish cards
 *   GET  /api/birthday-wishes       (auth: general_admin) today's posted wishes, for management
 *   POST /api/birthday-wishes       (auth: general_admin) { personType, personId?, name, photoUrl?, message }
 *   DELETE /api/birthday-wishes/:id (auth: general_admin)
 */
async function todaysBirthdayPeople(env) {
  const { results: students } = await env.DB
    .prepare(
      `SELECT s.id, s.name, s.guardian_phone AS phone, s.photo_key AS photo, c.name AS class_name
       FROM students s LEFT JOIN classes c ON c.id = s.class_id
       WHERE s.status = 'active' AND s.dob IS NOT NULL
         AND strftime('%m-%d', s.dob) = strftime('%m-%d', 'now', '+1 hour')
       ORDER BY s.name COLLATE NOCASE`
    )
    .all();

  const { results: staff } = await env.DB
    .prepare(
      `SELECT id, name, phone, role
       FROM users
       WHERE status = 'active' AND dob IS NOT NULL
         AND strftime('%m-%d', dob) = strftime('%m-%d', 'now', '+1 hour')
       ORDER BY name`
    )
    .all();

  return [
    ...students.map(s => ({ id: s.id, type: "student", name: s.name, class_name: s.class_name, phone: s.phone, photo: s.photo })),
    ...staff.map(t => ({ id: t.id, type: "staff", name: t.name, role: t.role, phone: t.phone }))
  ];
}


// ---- Automatic birthday wishes -------------------------------------------
// Staff wishes are published straight away. Student wishes are created as
// "pending" so the General Admin can review/edit and approve them before
// they appear on the public homepage. Runs lazily (whenever the homepage or
// the admin panel asks) and is idempotent — one wish per person per day.
const STAFF_WISH_TEMPLATES = [
  "Happy Birthday! Thank you for your dedication and care. The whole FIS Itobe family celebrates you today. May God bless you abundantly.",
  "Wishing you a joyful birthday and a year full of good health, peace and success. We are grateful to have you on our team.",
  "Today we celebrate you! Thank you for shaping young lives with love and commitment. Happy Birthday from all of us at FIS Itobe.",
  "Happy Birthday! May the Lord grant you many more years, strength for every task and joy in all you do."
];
const STUDENT_WISH_TEMPLATES = [
  "Happy Birthday! Everyone at Faith International School Itobe is celebrating you today. May God bless you and make this year your best yet.",
  "Wishing you a wonderful birthday full of joy and laughter. Keep learning, keep shining. In God We Trust!",
  "Today is your special day! May God guide you, grant you wisdom and fill your year with success. Happy Birthday from your FIS Itobe family.",
  "Happy Birthday! We are proud of you. May this new year bring you good health, great grades and lots of happiness."
];

function pickTemplate(list, seed) {
  let h = 0;
  const str = String(seed);
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return list[h % list.length];
}

// Sends one birthday SMS and records the outcome on the wish row.
// Returns 'sent' | 'failed' | 'skipped' (no phone on file).
async function sendBirthdaySms(env, { wishId, phone, name, message, type, personId, sentBy }) {
  let status;
  let detail = null;
  const text = type === "staff"
    ? `[FIS Itobe] Dear ${name}, ${message}`
    : `[FIS Itobe] ${name}: ${message}`;

  if (!phone) {
    status = "skipped";
  } else {
    const result = await sendKudiSms(env, phone, text);
    status = result.ok ? "sent" : "failed";
    detail = result.detail;
    await logSms(env, {
      category: "birthdays", phone, label: name, message: text,
      status, detail, studentId: type === "student" ? personId : null, sentBy: sentBy || null
    });
  }

  await env.DB.prepare("UPDATE birthday_wishes SET sms_status = ? WHERE id = ?").bind(status, wishId).run();
  return status;
}

async function syncTodaysBirthdayWishes(env) {
  const people = await todaysBirthdayPeople(env);
  for (const p of people) {
    const isStaff = p.type === "staff";
    const message = pickTemplate(isStaff ? STAFF_WISH_TEMPLATES : STUDENT_WISH_TEMPLATES, p.id);
    const wishId = uuid();
    const res = await env.DB
      .prepare(
        `INSERT OR IGNORE INTO birthday_wishes
           (id, person_type, person_id, name, photo_url, message, wish_date, status, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, date('now', '+1 hour'), 'approved', 'auto', datetime('now'))`
      )
      .bind(wishId, p.type, p.id, p.name, isStaff ? null : (p.photo || null), message)
      .run();

    // Staff: text them automatically, but only for the request that actually
    // created today's wish (the unique index makes repeats no-ops).
    const created = res && res.meta && res.meta.changes === 1;

    // Students appear on the homepage straight away; only their guardian SMS
    // waits for the admin ('pending'), or is skipped when there is no phone.
    if (!isStaff && created) {
      await env.DB
        .prepare("UPDATE birthday_wishes SET sms_status = ? WHERE id = ?")
        .bind(p.phone ? "pending" : "skipped", wishId)
        .run();
    }

    if (isStaff && created) {
      try {
        await sendBirthdaySms(env, { wishId, phone: p.phone, name: p.name, message, type: "staff", personId: p.id });
      } catch (err) {
        // A failed text must never stop the homepage from loading.
      }
    }
  }
}

async function handleBirthdayRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- ADMIN: TODAY'S AUTO-DETECTED LIST ----------------
  if (pathname === "/api/birthdays/today" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    try {
      const birthdays = await todaysBirthdayPeople(env);
      return json({ birthdays });
    } catch (err) {
      return json({ error: "Could not check birthdays. Has the users.dob column been added?", detail: String((err && err.message) || err) }, 500);
    }
  }

  // ---------------- ADMIN: SEND BIRTHDAY SMS FOR TODAY ----------------
  if (pathname === "/api/sms/notify-birthdays" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. SMS is restricted to the General Admin." }, 403);

    const { message } = await request.json();
    if (!message || !message.trim()) return json({ error: "message is required." }, 400);

    const people = await todaysBirthdayPeople(env);
    if (!people.length) return json({ error: "No one is celebrating a birthday today." }, 404);

    const sent = [];
    const failed = [];
    const skipped = [];

    await Promise.all(people.map(async (p) => {
      if (!p.phone) {
        skipped.push({ name: p.name, reason: "No phone number on file." });
        return;
      }
      const result = await sendKudiSms(env, p.phone, message);
      await logSms(env, {
        category: "birthdays", phone: p.phone, label: p.name, message,
        status: result.ok ? "sent" : "failed", detail: result.detail,
        studentId: p.type === "student" ? p.id : null, sentBy: sessionCtx.id
      });
      if (result.ok) sent.push({ name: p.name });
      else failed.push({ name: p.name, reason: result.detail });
    }));

    return json({
      message: `Sent ${sent.length}, failed ${failed.length}, skipped ${skipped.length}.`,
      sent, failed, skipped
    });
  }

  // ---------------- PUBLIC: TODAY'S POSTED WISH CARDS ----------------
  if (pathname === "/api/public/birthdays" && request.method === "GET") {
    try {
      await syncTodaysBirthdayWishes(env);
      const { results } = await env.DB
        .prepare(
          `SELECT id, name, photo_url, message FROM birthday_wishes
           WHERE wish_date = date('now', '+1 hour') AND status = 'approved' ORDER BY created_at ASC`
        )
        .all();
      return json({ wishes: results });
    } catch (err) {
      return json({ error: "birthday_wishes table not found — run the migration first.", detail: String((err && err.message) || err) }, 500);
    }
  }

  // ---------------- ADMIN: TODAY'S POSTED WISHES (management) ----------------
  if (pathname === "/api/birthday-wishes" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    try {
      await syncTodaysBirthdayWishes(env);
      const { results } = await env.DB
        .prepare(
          `SELECT bw.*,
                  COALESCE((SELECT guardian_phone FROM students WHERE id = bw.person_id AND bw.person_type = 'student'),
                           (SELECT phone FROM users WHERE id = bw.person_id AND bw.person_type = 'staff')) AS phone
           FROM birthday_wishes bw
           WHERE bw.wish_date = date('now', '+1 hour') AND bw.status != 'rejected'
           ORDER BY (bw.sms_status = 'pending') DESC, bw.created_at ASC`
        )
        .all();
      return json({ wishes: results, pendingCount: results.filter(w => w.person_type === "student" && w.sms_status === "pending").length });
    } catch (err) {
      return json({ error: "birthday_wishes table not found — run the migration first.", detail: String((err && err.message) || err) }, 500);
    }
  }

  // ---------------- ADMIN: POST A WISH ----------------
  if (pathname === "/api/birthday-wishes" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { personType, personId, name, photoUrl, message } = await request.json();
    if (!name || !message || !message.trim()) {
      return json({ error: "name and message are required." }, 400);
    }
    if (personType && !["student", "staff"].includes(personType)) {
      return json({ error: "personType must be 'student' or 'staff'." }, 400);
    }

    const id = uuid();
    await env.DB
      .prepare(
        `INSERT INTO birthday_wishes (id, person_type, person_id, name, photo_url, message, wish_date, created_at)
         VALUES (?, ?, ?, ?, ?, ?, date('now', '+1 hour'), datetime('now'))`
      )
      .bind(id, personType || null, personId || null, name, photoUrl || null, message.trim())
      .run();

    return json({ message: "Birthday wish posted to the public page.", id });
  }

  // ---------------- ADMIN: EDIT MESSAGE / HIDE / APPROVE OR SKIP THE GUARDIAN SMS ----------------
  const wishPatchMatch = pathname.match(/^\/api\/birthday-wishes\/([^/]+)$/);
  if (wishPatchMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { status, message, smsAction } = await request.json();
    if (status && !["approved", "rejected"].includes(status)) {
      return json({ error: "status must be approved or rejected." }, 400);
    }
    if (smsAction && !["send", "skip"].includes(smsAction)) {
      return json({ error: "smsAction must be send or skip." }, 400);
    }
    if (message !== undefined && !String(message).trim()) {
      return json({ error: "The message cannot be empty." }, 400);
    }

    const existing = await env.DB.prepare("SELECT * FROM birthday_wishes WHERE id = ?").bind(wishPatchMatch[1]).first();
    if (!existing) return json({ error: "Wish not found." }, 404);

    const finalMessage = message !== undefined ? String(message).trim() : existing.message;

    await env.DB
      .prepare("UPDATE birthday_wishes SET status = COALESCE(?, status), message = ? WHERE id = ?")
      .bind(status || null, finalMessage, wishPatchMatch[1])
      .run();

    if (status === "rejected") return json({ message: "Removed from the homepage." });

    if (smsAction === "skip" && existing.sms_status === "pending") {
      await env.DB.prepare("UPDATE birthday_wishes SET sms_status = 'declined' WHERE id = ?").bind(existing.id).run();
      return json({ message: "No SMS will be sent to the guardian." });
    }

    if (smsAction === "send" && existing.person_type === "student" && existing.person_id && existing.sms_status === "pending") {
      const stu = await env.DB.prepare("SELECT guardian_phone FROM students WHERE id = ?").bind(existing.person_id).first();
      const smsStatus = await sendBirthdaySms(env, {
        wishId: existing.id, phone: stu && stu.guardian_phone, name: existing.name,
        message: finalMessage, type: "student", personId: existing.person_id, sentBy: sessionCtx.id
      });
      return json({
        message: smsStatus === "sent" ? "SMS sent to the guardian."
          : smsStatus === "skipped" ? "No guardian phone on file, so no SMS was sent."
          : "The SMS could not be sent. Check the SMS log."
      });
    }

    return json({ message: "Saved." });
  }

  // ---------------- ADMIN: DELETE A WISH ----------------
  const wishDeleteMatch = pathname.match(/^\/api\/birthday-wishes\/([^/]+)$/);
  if (wishDeleteMatch && request.method === "DELETE") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const row = await env.DB.prepare("SELECT source FROM birthday_wishes WHERE id = ?").bind(wishDeleteMatch[1]).first();
    if (row && row.source === "auto") {
      // Keep the row (hidden) so the automatic sync doesn't recreate it today.
      await env.DB.prepare("UPDATE birthday_wishes SET status = 'rejected' WHERE id = ?").bind(wishDeleteMatch[1]).run();
    } else {
      await env.DB.prepare("DELETE FROM birthday_wishes WHERE id = ?").bind(wishDeleteMatch[1]).run();
    }
    return json({ message: "Wish removed." });
  }

  return null; // not handled here — let the router try the next module
}


// =====================================================================
// SECTION 7B5: Audit trail (who changed what, and when)
// =====================================================================
/**
 * Every successful change (POST / PATCH / DELETE) made by a logged-in
 * staff member is recorded automatically by the router below — request
 * bodies are never stored, so passwords and PINs can't leak into it.
 *
 * One-time D1 migration:
 *
 * CREATE TABLE audit_log (
 *   id TEXT PRIMARY KEY,
 *   actor_id TEXT,
 *   actor_name TEXT,
 *   actor_role TEXT,
 *   method TEXT NOT NULL,
 *   path TEXT NOT NULL,
 *   status INTEGER,
 *   created_at TEXT NOT NULL
 * );
 * CREATE INDEX idx_audit_created ON audit_log(created_at);
 *
 * Route:
 *   GET /api/audit?limit=  (auth: general_admin) newest first, max 500
 */
const AUDIT_SKIP_PATHS = ["/api/login", "/api/student-login", "/api/refresh", "/api/signup", "/api/admissions/apply", "/api/audit"];

async function recordAudit(request, env, url, response) {
  try {
    if (!["POST", "PATCH", "DELETE"].includes(request.method)) return;
    if (response.status >= 400) return;
    if (url.pathname.startsWith("/api/public/") || AUDIT_SKIP_PATHS.includes(url.pathname)) return;

    const session = await getSession(request, env);
    if (!session || session.type !== "staff") return;

    await env.DB
      .prepare(
        `INSERT INTO audit_log (id, actor_id, actor_name, actor_role, method, path, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(uuid(), session.id, session.record.name || null, session.role || null, request.method, url.pathname, response.status)
      .run();
  } catch (err) {
    // Auditing must never break the request it is recording.
  }
}

async function handleAuditRoutes(request, env, url) {
  if (url.pathname === "/api/audit" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit"), 10) || 200, 1), 500);
    try {
      const { results } = await env.DB
        .prepare("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?")
        .bind(limit)
        .all();
      return json({ entries: results });
    } catch (err) {
      return json({ error: "audit_log table not found — run the migration first.", detail: String((err && err.message) || err) }, 500);
    }
  }
  return null;
}

// =====================================================================
/**
 * FIS Itobe Portal — Worker API (Results: score entry & approval)
 *
 * Grading uses the school's existing WAEC-style scale:
 *   A1 75-100, B2 70-74, B3 65-69, C4 60-64, C5 55-59, C6 50-54,
 *   D7 45-49, E8 40-44, F9 0-39
 *
 * Routes:
 *   POST /api/results                  (auth: teaching staff) enter/update one student's score
 *        body: { studentId, classId, subjectId, term, session, ca1, ca2, exam }
 *        — recomputes total/grade and resets status to 'pending' on every save
 *   GET  /api/results?classId=&subjectId=&term=&session=   (auth: teaching staff)
 *        every student in the class with their score for that subject/term/session (or none yet)
 *   GET  /api/results/pending?classId=&term=&session=      (auth: admin)
 *        all pending results for a class/term/session, across every subject
 *   PATCH /api/results/:id             (auth: admin) { status: 'approved' | 'withheld' }
 *   POST /api/results/approve-class    (auth: admin) { classId, term, session }
 *        bulk-approves every pending result for that class/term/session
 */

function computeGrade(total) {
  if (total === null || total === undefined || isNaN(total)) return null;
  if (total >= 75) return "A1";
  if (total >= 70) return "B2";
  if (total >= 65) return "B3";
  if (total >= 60) return "C4";
  if (total >= 55) return "C5";
  if (total >= 50) return "C6";
  if (total >= 45) return "D7";
  if (total >= 40) return "E8";
  return "F9";
}

async function handleResultsRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- ENTER / UPDATE A SCORE ----------------
  if (pathname === "/api/results" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { studentId, classId, subjectId, term, session, ca1, ca2, exam } = await request.json();
    if (!studentId || !classId || !subjectId || !term || !session) {
      return json({ error: "studentId, classId, subjectId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const ca1Val = ca1 === "" || ca1 === undefined || ca1 === null ? null : Number(ca1);
    const ca2Val = ca2 === "" || ca2 === undefined || ca2 === null ? null : Number(ca2);
    const examVal = exam === "" || exam === undefined || exam === null ? null : Number(exam);

    if (ca1Val !== null && (isNaN(ca1Val) || ca1Val < 0 || ca1Val > 15)) {
      return json({ error: "CA1 must be between 0 and 15." }, 400);
    }
    if (ca2Val !== null && (isNaN(ca2Val) || ca2Val < 0 || ca2Val > 15)) {
      return json({ error: "CA2 must be between 0 and 15." }, 400);
    }
    if (examVal !== null && (isNaN(examVal) || examVal < 0 || examVal > 70)) {
      return json({ error: "Exam must be between 0 and 70." }, 400);
    }

    const total = (ca1Val || 0) + (ca2Val || 0) + (examVal || 0);
    const grade = computeGrade(total);

    const existing = await env.DB
      .prepare("SELECT id FROM results WHERE student_id = ? AND subject_id = ? AND term = ? AND session = ?")
      .bind(studentId, subjectId, term, session)
      .first();

    if (existing) {
      await env.DB
        .prepare(
          `UPDATE results SET ca1 = ?, ca2 = ?, exam = ?, grade = ?, status = 'pending',
                  entered_by = ?, updated_at = datetime('now')
           WHERE id = ?`
        )
        .bind(ca1Val, ca2Val, examVal, grade, sessionCtx.id, existing.id)
        .run();
    } else {
      await env.DB
        .prepare(
          `INSERT INTO results (id, student_id, class_id, subject_id, term, session, ca1, ca2, exam, grade, status, entered_by, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`
        )
        .bind(uuid(), studentId, classId, subjectId, term, session, ca1Val, ca2Val, examVal, grade, sessionCtx.id)
        .run();
    }

    return json({ message: "Score saved.", total, grade });
  }

  // ---------------- LIST SCORES FOR A CLASS/SUBJECT ----------------
  if (pathname === "/api/results" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = url.searchParams.get("classId");
    const subjectId = url.searchParams.get("subjectId");
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!classId || !subjectId || !term || !session) {
      return json({ error: "classId, subjectId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT s.id AS student_id, s.name AS student_name, s.admission_no,
                r.id AS result_id, r.ca1, r.ca2, r.exam, r.grade, r.status
         FROM students s
         LEFT JOIN results r
           ON r.student_id = s.id AND r.subject_id = ? AND r.term = ? AND r.session = ?
         WHERE s.class_id = ? AND s.status = 'active'
         ORDER BY s.name COLLATE NOCASE`
      )
      .bind(subjectId, term, session, classId)
      .all();

    return json({ students: results });
  }

  // ---------------- LIST PENDING/WITHHELD RESULTS FOR A CLASS ----------------
  if (pathname === "/api/results/pending" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = url.searchParams.get("classId");
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    const status = url.searchParams.get("status") || "pending";
    if (!classId || !term || !session) {
      return json({ error: "classId, term, and session are required." }, 400);
    }
    if (!["pending", "withheld"].includes(status)) {
      return json({ error: "status must be 'pending' or 'withheld'." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results } = await env.DB
      .prepare(
        `SELECT r.id, r.ca1, r.ca2, r.exam, r.grade, r.status,
                s.name AS student_name, sub.name AS subject_name
         FROM results r
         JOIN students s ON s.id = r.student_id
         JOIN subjects sub ON sub.id = r.subject_id
         WHERE r.class_id = ? AND r.term = ? AND r.session = ? AND r.status = ?
         ORDER BY s.name COLLATE NOCASE, sub.name`
      )
      .bind(classId, term, session, status)
      .all();

    return json({ results });
  }

  // ---------------- VIEW ALL STUDENTS + THEIR RESULT STATUS FOR A CLASS ----------------
  if (pathname === "/api/results/student-status" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const classId = url.searchParams.get("classId");
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    if (!classId || !term || !session) {
      return json({ error: "classId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const { results: rows } = await env.DB
      .prepare(
        `SELECT s.id AS student_id, s.name AS student_name, s.admission_no,
                r.status
         FROM students s
         LEFT JOIN results r
           ON r.student_id = s.id AND r.class_id = ? AND r.term = ? AND r.session = ?
         WHERE s.class_id = ? AND s.status = 'active'
         ORDER BY s.name COLLATE NOCASE`
      )
      .bind(classId, term, session, classId)
      .all();

    const byStudent = {};
    for (const row of rows) {
      if (!byStudent[row.student_id]) {
        byStudent[row.student_id] = {
          student_id: row.student_id,
          student_name: row.student_name,
          admission_no: row.admission_no,
          total: 0,
          approved: 0,
          pending: 0,
          withheld: 0
        };
      }
      if (row.status) {
        byStudent[row.student_id].total++;
        byStudent[row.student_id][row.status]++;
      }
    }

    const students = Object.values(byStudent).map(st => {
      let overall = "none"; // no results entered at all
      if (st.total > 0) {
        if (st.approved === st.total) overall = "approved";
        else if (st.withheld === st.total) overall = "withheld";
        else if (st.pending === st.total) overall = "pending";
        else overall = "mixed";
      }
      return { ...st, overall };
    });

    return json({ students });
  }

  // ---------------- APPROVE / WITHHOLD ONE RESULT ----------------
  const resultDetailMatch = pathname.match(/^\/api\/results\/([^/]+)$/);
  if (resultDetailMatch && request.method === "PATCH") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const resultId = resultDetailMatch[1];
    const { status } = await request.json();
    if (!["approved", "withheld", "pending"].includes(status)) {
      return json({ error: "status must be 'approved', 'withheld', or 'pending'." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const row = await env.DB
        .prepare(`SELECT c.level FROM results r JOIN classes c ON c.id = r.class_id WHERE r.id = ?`)
        .bind(resultId)
        .first();
      if (!row || row.level !== restriction) return json({ error: "Not authorised for this result." }, 403);
    }

    await env.DB
      .prepare("UPDATE results SET status = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(status, resultId)
      .run();

    return json({ message: "Result " + status + "." });
  }

  // ---------------- BULK-APPROVE ALL PENDING FOR A CLASS ----------------
  if (pathname === "/api/results/approve-class" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { classId, term, session } = await request.json();
    if (!classId || !term || !session) {
      return json({ error: "classId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    await env.DB
      .prepare(
        `UPDATE results SET status = 'approved', updated_at = datetime('now')
         WHERE class_id = ? AND term = ? AND session = ? AND status = 'pending'`
      )
      .bind(classId, term, session)
      .run();

    return json({ message: "All pending results approved." });
  }

  // ---------------- RELEASE ALL RESULTS FOR A CLASS/TERM/SESSION ----------------
  if (pathname === "/api/results/release-class" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { classId, term, session } = await request.json();
    if (!classId || !term || !session) {
      return json({ error: "classId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    await env.DB
      .prepare(
        `UPDATE results SET status = 'approved', updated_at = datetime('now')
         WHERE class_id = ? AND term = ? AND session = ?`
      )
      .bind(classId, term, session)
      .run();

    return json({ message: "All results released for this class/term/session." });
  }

  // ---------------- WITHHOLD ALL RESULTS FOR A CLASS/TERM/SESSION ----------------
  if (pathname === "/api/results/withhold-class" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { classId, term, session } = await request.json();
    if (!classId || !term || !session) {
      return json({ error: "classId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    await env.DB
      .prepare(
        `UPDATE results SET status = 'withheld', updated_at = datetime('now')
         WHERE class_id = ? AND term = ? AND session = ?`
      )
      .bind(classId, term, session)
      .run();

    return json({ message: "All results withheld for this class/term/session." });
  }

  // ---------------- RELEASE / WITHHOLD ALL RESULTS FOR SELECTED STUDENTS ----------------
  const resultsBulkStudentsMatch = pathname.match(/^\/api\/results\/(release|withhold)-students$/);
  if (resultsBulkStudentsMatch && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const action = resultsBulkStudentsMatch[1]; // "release" | "withhold"
    const newStatus = action === "release" ? "approved" : "withheld";

    const { classId, term, session, studentIds } = await request.json();
    if (!classId || !term || !session || !Array.isArray(studentIds) || studentIds.length === 0) {
      return json({ error: "classId, term, session, and at least one studentId are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    if (restriction) {
      const cls = await env.DB.prepare("SELECT level FROM classes WHERE id = ?").bind(classId).first();
      if (!cls || cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);
    }

    const placeholders = studentIds.map(() => "?").join(",");
    await env.DB
      .prepare(
        `UPDATE results SET status = ?, updated_at = datetime('now')
         WHERE class_id = ? AND term = ? AND session = ? AND student_id IN (${placeholders})`
      )
      .bind(newStatus, classId, term, session, ...studentIds)
      .run();

    return json({
      message: `Results ${action === "release" ? "released" : "withheld"} for ${studentIds.length} student${studentIds.length === 1 ? "" : "s"}.`
    });
  }

  return null; // not handled here — let the router try the next module
}

// =====================================================================
// SECTION 7J: SMS routes (results notifications + free-text broadcasts)
// =====================================================================
/**
 * Uses KudiSMS (https://kudisms.net) — Nigeria-focused bulk SMS API.
 * Requires two things set in the Worker's environment before this will
 * actually send anything:
 *   - KUDISMS_API_KEY     (Cloudflare Secret — your KudiSMS API token)
 *   - KUDISMS_SENDER_ID   (Variable — falls back to the hardcoded
 *                          "FISS ITOBE" approved Sender ID below)
 * Sends via GET https://my.kudisms.net/api/sms with gateway=2 ("Refunds
 * Charge for DND Numbers" — DND-registered recipients still won't
 * actually receive the text, but you aren't billed for the attempt).
 * A successful response looks like
 * { status: "success", error_code: "000", data: ["234...|<msg-id>"], ... }.
 * Requires a `sms_log` table (see migration note at the bottom of this
 * section) — not created automatically, run it once via wrangler/D1 console.
 *
 * Routes:
 *   POST /api/sms/notify-results  (auth: general_admin only)
 *        { classId, term, session, studentIds?: [] }
 *        Texts guardians of students who have at least one APPROVED
 *        result for that term/session. Without studentIds, targets every
 *        active student in the class with an approved result.
 *   POST /api/sms/notify-fees     (auth: general_admin only)
 *        { classId, term, session, studentIds?: [] }
 *        Texts guardians of students with an outstanding fee balance
 *        (feeAmount - totalPaid > 0) for that term/session. Without
 *        studentIds, targets every active student in the class.
 *   POST /api/sms/notify-teachers (auth: general_admin only)
 *        { staffIds?: [], message }
 *        Texts active teachers their registered phone number (users.phone).
 *        Without staffIds, targets every active teacher. Staff with no
 *        phone on file are skipped and listed, same as the other routes.
 *   POST /api/sms/broadcast       (auth: general_admin only)
 *        { phones: [ "080...", "070..." ], message, label? }
 *        Sends free-text to any phone numbers typed/pasted in directly —
 *        for parents, teachers, or anyone else. Not tied to student records.
 *   GET  /api/sms/log             (auth: general_admin only)
 *        ?classId=&term=&session=&category=&limit=
 *        Recent send history for troubleshooting/audit.
 */

function normalizeNigerianPhone(raw) {
  let p = String(raw || "").trim().replace(/[^\d+]/g, "");
  if (p.startsWith("+")) p = p.slice(1);
  if (p.startsWith("0")) p = "234" + p.slice(1);
  else if (p.length === 10 && !p.startsWith("234")) p = "234" + p;
  return p;
}

async function sendKudiSms(env, toRaw, message) {
  const apiKey = env.KUDISMS_API_KEY;
  if (!apiKey) return { ok: false, detail: "KUDISMS_API_KEY is not configured on the Worker." };

  const to = normalizeNigerianPhone(toRaw);
  if (!to || to.length < 11) return { ok: false, detail: "Invalid phone number: " + toRaw };

  try {
    const params = new URLSearchParams({
      token: apiKey,
      senderID: env.KUDISMS_SENDER_ID || "FISS ITOBE",
      recipients: to,
      message,
      gateway: "2" // refunds charge for DND numbers (they still won't receive the SMS)
    });
    const res = await fetch(`https://my.kudisms.net/api/sms?${params.toString()}`, { method: "GET" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data || data.status !== "success" || data.error_code !== "000") {
      return { ok: false, detail: (data && (data.msg || JSON.stringify(data))) || `HTTP ${res.status}` };
    }
    const messageId = Array.isArray(data.data) ? data.data[0] : undefined;
    return { ok: true, detail: messageId };
  } catch (err) {
    return { ok: false, detail: String((err && err.message) || err) };
  }
}

async function logSms(env, row) {
  try {
    await env.DB
      .prepare(
        `INSERT INTO sms_log (id, category, recipient_phone, recipient_label, message, status, provider_detail,
                               student_id, class_id, term, session, sent_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(
        uuid(), row.category, row.phone, row.label || null, row.message, row.status, row.detail || null,
        row.studentId || null, row.classId || null, row.term || null, row.session || null, row.sentBy || null
      )
      .run();
  } catch (err) {
    // Logging failures shouldn't block the actual send response — the
    // sms_log table may not exist yet (see migration note above).
  }
}

async function handleSmsRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- NOTIFY PARENTS OF RELEASED RESULTS ----------------
  if (pathname === "/api/sms/notify-results" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. SMS is restricted to the General Admin." }, 403);

    const { classId, term, session, studentIds } = await request.json();
    if (!classId || !term || !session) {
      return json({ error: "classId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    const cls = await env.DB.prepare("SELECT id, name, level FROM classes WHERE id = ?").bind(classId).first();
    if (!cls) return json({ error: "Class not found." }, 404);
    if (restriction && cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);

    let students;
    if (Array.isArray(studentIds) && studentIds.length > 0) {
      const placeholders = studentIds.map(() => "?").join(",");
      const { results } = await env.DB
        .prepare(`SELECT id, name, guardian_phone FROM students WHERE class_id = ? AND id IN (${placeholders})`)
        .bind(classId, ...studentIds)
        .all();
      students = results;
    } else {
      const { results } = await env.DB
        .prepare("SELECT id, name, guardian_phone FROM students WHERE class_id = ? AND status = 'active'")
        .bind(classId)
        .all();
      students = results;
    }

    if (!students.length) return json({ error: "No matching students found." }, 404);

    // Class-wide averages (approved results only) — used to compute each
    // student's average score and rank/position, same logic as the report card.
    const { results: classAverages } = await env.DB
      .prepare(
        `SELECT student_id, AVG(ca1 + ca2 + exam) AS avg_score
         FROM results
         WHERE class_id = ? AND term = ? AND session = ? AND status = 'approved'
         GROUP BY student_id
         ORDER BY avg_score DESC`
      )
      .bind(classId, term, session)
      .all();

    const outOf = classAverages.length;
    const rankById = {};
    classAverages.forEach((row, idx) => { rankById[row.student_id] = idx + 1; });
    const avgById = {};
    classAverages.forEach(row => { avgById[row.student_id] = row.avg_score; });

    function ordinal(n) {
      const s = ["th", "st", "nd", "rd"];
      const v = n % 100;
      return n + (s[(v - 20) % 10] || s[v] || s[0]);
    }

    const sent = [];
    const failed = [];
    const skipped = [];

    await Promise.all(students.map(async (stu) => {
      const approvedRow = await env.DB
        .prepare(
          `SELECT COUNT(*) AS count FROM results
           WHERE student_id = ? AND class_id = ? AND term = ? AND session = ? AND status = 'approved'`
        )
        .bind(stu.id, classId, term, session)
        .first();

      if (!approvedRow || approvedRow.count === 0) {
        skipped.push({ studentId: stu.id, name: stu.name, reason: "No released result for this term/session." });
        return;
      }
      if (!stu.guardian_phone) {
        skipped.push({ studentId: stu.id, name: stu.name, reason: "No guardian phone number on file." });
        return;
      }

      const avg = avgById[stu.id];
      const position = rankById[stu.id];
      const summary = (avg !== undefined && position)
        ? ` Avg: ${avg.toFixed(1)}%, Position: ${ordinal(position)} of ${outOf}.`
        : "";

      const message = `${term} (${session}) result for ${stu.name} (${cls.name}) is out.${summary} View full result on the school portal.`;

      const result = await sendKudiSms(env, stu.guardian_phone, message);
      await logSms(env, {
        category: "results", phone: stu.guardian_phone, label: stu.name, message,
        status: result.ok ? "sent" : "failed", detail: result.detail,
        studentId: stu.id, classId, term, session, sentBy: sessionCtx.id
      });

      if (result.ok) sent.push({ studentId: stu.id, name: stu.name });
      else failed.push({ studentId: stu.id, name: stu.name, reason: result.detail });
    }));

    return json({
      message: `Sent ${sent.length}, failed ${failed.length}, skipped ${skipped.length}.`,
      sent, failed, skipped
    });
  }

  // ---------------- NOTIFY PARENTS OF OUTSTANDING FEE BALANCES ----------------
  if (pathname === "/api/sms/notify-fees" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. SMS is restricted to the General Admin." }, 403);

    const { classId, term, session, studentIds } = await request.json();
    if (!classId || !term || !session) {
      return json({ error: "classId, term, and session are required." }, 400);
    }

    const restriction = adminLevelRestriction(sessionCtx);
    const cls = await env.DB.prepare("SELECT id, name, level FROM classes WHERE id = ?").bind(classId).first();
    if (!cls) return json({ error: "Class not found." }, 404);
    if (restriction && cls.level !== restriction) return json({ error: "Not authorised for this class." }, 403);

    const structure = await env.DB
      .prepare("SELECT amount FROM fee_structures WHERE class_id = ? AND term = ? AND session = ?")
      .bind(classId, term, session)
      .first();
    const feeAmount = structure ? structure.amount : 0;

    let students;
    if (Array.isArray(studentIds) && studentIds.length > 0) {
      const placeholders = studentIds.map(() => "?").join(",");
      const { results } = await env.DB
        .prepare(`SELECT id, name, guardian_phone FROM students WHERE class_id = ? AND id IN (${placeholders})`)
        .bind(classId, ...studentIds)
        .all();
      students = results;
    } else {
      const { results } = await env.DB
        .prepare("SELECT id, name, guardian_phone FROM students WHERE class_id = ? AND status = 'active'")
        .bind(classId)
        .all();
      students = results;
    }

    if (!students.length) return json({ error: "No matching students found." }, 404);

    const sent = [];
    const failed = [];
    const skipped = [];

    await Promise.all(students.map(async (stu) => {
      const paidRow = await env.DB
        .prepare("SELECT COALESCE(SUM(amount), 0) AS total FROM fee_transactions WHERE student_id = ? AND term = ? AND session = ?")
        .bind(stu.id, term, session)
        .first();
      const balance = feeAmount - paidRow.total;

      if (balance <= 0) {
        skipped.push({ studentId: stu.id, name: stu.name, reason: "No outstanding balance." });
        return;
      }
      if (!stu.guardian_phone) {
        skipped.push({ studentId: stu.id, name: stu.name, reason: "No guardian phone number on file." });
        return;
      }

      const message = `Fee reminder: ${stu.name} (${cls.name}) has an outstanding balance of NGN ${balance.toLocaleString()} for ${term} (${session}). Kindly clear at your earliest convenience. - Faith International Schools, Itobe`;

      const result = await sendKudiSms(env, stu.guardian_phone, message);
      await logSms(env, {
        category: "fees", phone: stu.guardian_phone, label: stu.name, message,
        status: result.ok ? "sent" : "failed", detail: result.detail,
        studentId: stu.id, classId, term, session, sentBy: sessionCtx.id
      });

      if (result.ok) sent.push({ studentId: stu.id, name: stu.name, balance });
      else failed.push({ studentId: stu.id, name: stu.name, reason: result.detail });
    }));

    return json({
      message: `Sent ${sent.length}, failed ${failed.length}, skipped ${skipped.length}.`,
      sent, failed, skipped
    });
  }

  // ---------------- NOTIFY TEACHERS (GENERAL ANNOUNCEMENTS) ----------------
  if (pathname === "/api/sms/notify-teachers" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. SMS is restricted to the General Admin." }, 403);

    const { staffIds, message } = await request.json();
    if (!message || !message.trim()) {
      return json({ error: "message is required." }, 400);
    }

    let teachers;
    if (Array.isArray(staffIds) && staffIds.length > 0) {
      const placeholders = staffIds.map(() => "?").join(",");
      const { results } = await env.DB
        .prepare(`SELECT id, name, phone FROM users WHERE role = 'teacher' AND status = 'active' AND id IN (${placeholders})`)
        .bind(...staffIds)
        .all();
      teachers = results;
    } else {
      const { results } = await env.DB
        .prepare("SELECT id, name, phone FROM users WHERE role = 'teacher' AND status = 'active'")
        .all();
      teachers = results;
    }

    if (!teachers.length) return json({ error: "No matching teachers found." }, 404);

    const sent = [];
    const failed = [];
    const skipped = [];

    await Promise.all(teachers.map(async (t) => {
      if (!t.phone) {
        skipped.push({ staffId: t.id, name: t.name, reason: "No phone number on file." });
        return;
      }

      const result = await sendKudiSms(env, t.phone, message);
      await logSms(env, {
        category: "teachers", phone: t.phone, label: t.name, message,
        status: result.ok ? "sent" : "failed", detail: result.detail,
        sentBy: sessionCtx.id
      });

      if (result.ok) sent.push({ staffId: t.id, name: t.name });
      else failed.push({ staffId: t.id, name: t.name, reason: result.detail });
    }));

    return json({
      message: `Sent ${sent.length}, failed ${failed.length}, skipped ${skipped.length}.`,
      sent, failed, skipped
    });
  }

  // ---------------- FREE-TEXT BROADCAST TO PROVIDED NUMBERS ----------------
  if (pathname === "/api/sms/broadcast" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. SMS is restricted to the General Admin." }, 403);

    const { phones, message, label } = await request.json();
    if (!Array.isArray(phones) || phones.length === 0 || !message || !message.trim()) {
      return json({ error: "phones (non-empty array) and message are required." }, 400);
    }

    const uniquePhones = [...new Set(phones.map(p => String(p || "").trim()).filter(Boolean))];
    if (!uniquePhones.length) return json({ error: "No valid phone numbers provided." }, 400);

    const sent = [];
    const failed = [];

    await Promise.all(uniquePhones.map(async (phone) => {
      const result = await sendKudiSms(env, phone, message);
      await logSms(env, {
        category: "broadcast", phone, label: label || null, message,
        status: result.ok ? "sent" : "failed", detail: result.detail,
        sentBy: sessionCtx.id
      });
      if (result.ok) sent.push(phone);
      else failed.push({ phone, reason: result.detail });
    }));

    return json({
      message: `Sent ${sent.length}, failed ${failed.length}.`,
      sent, failed
    });
  }

  // ---------------- SEND LOG ----------------
  if (pathname === "/api/sms/log" && request.method === "GET") {
    const sessionCtx = await getSession(request, env);
    if (!isGeneralAdmin(sessionCtx)) return json({ error: "Not authorised. SMS is restricted to the General Admin." }, 403);

    const classId = url.searchParams.get("classId");
    const term = url.searchParams.get("term");
    const session = url.searchParams.get("session");
    const category = url.searchParams.get("category");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 200);

    const conditions = [];
    const binds = [];
    if (classId) { conditions.push("class_id = ?"); binds.push(classId); }
    if (term) { conditions.push("term = ?"); binds.push(term); }
    if (session) { conditions.push("session = ?"); binds.push(session); }
    if (category) { conditions.push("category = ?"); binds.push(category); }
    const where = conditions.length ? "WHERE " + conditions.join(" AND ") : "";

    try {
      const { results } = await env.DB
        .prepare(`SELECT * FROM sms_log ${where} ORDER BY created_at DESC LIMIT ${limit}`)
        .bind(...binds)
        .all();
      return json({ log: results });
    } catch (err) {
      return json({ error: "sms_log table not found — run the migration first.", detail: String((err && err.message) || err) }, 500);
    }
  }

  return null; // not handled here — let the router try the next module
}

/**
 * One-time D1 migration for the sms_log table (run via wrangler or the
 * Cloudflare D1 console — this file only queries it, it never creates it):
 *
 * CREATE TABLE sms_log (
 *   id TEXT PRIMARY KEY,
 *   category TEXT NOT NULL,             -- 'results' | 'fees' | 'teachers' | 'broadcast'
 *   recipient_phone TEXT NOT NULL,
 *   recipient_label TEXT,               -- student/contact name, if known
 *   message TEXT NOT NULL,
 *   status TEXT NOT NULL,               -- 'sent' | 'failed'
 *   provider_detail TEXT,               -- KudiSMS message id, or error text
 *   student_id TEXT,
 *   class_id TEXT,
 *   term TEXT,
 *   session TEXT,
 *   sent_by TEXT,
 *   created_at TEXT NOT NULL
 * );
 *
 * One-time D1 migration to add a phone column to users (needed so
 * teachers can be texted via /api/sms/notify-teachers):
 *
 * ALTER TABLE users ADD COLUMN phone TEXT;
 *
 * One-time D1 migration to add a date-of-birth column to students
 * (needed so it can be shown on the printed report card — set per
 * student via the Roster tool's Edit form, PATCH /api/students/:id):
 *
 * ALTER TABLE students ADD COLUMN dob TEXT;
 *
 * One-time D1 migration to add a next-class link to classes (needed for
 * the Promotion tool — set per class via PATCH /api/classes/:id, used to
 * pre-fill the destination class when promoting a class's students):
 *
 * ALTER TABLE classes ADD COLUMN next_class_id TEXT;
 *
 * One-time D1 migration to add PIN lockout tracking to student_pins
 * (needed for the login hardening in handleStudentAuthRoutes — counts
 * consecutive wrong PINs per term/session and locks that PIN out for a
 * cooldown once PIN_LOCK_THRESHOLD is hit; a freshly (re)generated PIN
 * always clears both columns immediately):
 *
 * ALTER TABLE student_pins ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
 * ALTER TABLE student_pins ADD COLUMN locked_until TEXT;
 *
 * One-time D1 migration to add reversible PIN storage to student_pins
 * (needed so an already-generated PIN can be reprinted — see encryptPin /
 * decryptPin and GET /api/students/:id/pin — without ever regenerating it
 * or storing it in plain text):
 *
 * ALTER TABLE student_pins ADD COLUMN pin_enc TEXT;
 *
 * (Gallery and birthday migrations are documented above their own route
 * handlers — see handleGalleryRoutes and handleBirthdayRoutes.)
 */

// =====================================================================
// SECTION 8: Entry point — routes across all sections above
// =====================================================================
const modules = [
  handleAuthRoutes,
  handleStudentAuthRoutes,
  handleAttendanceRoutes,
  handleTimetableRoutes,
  handleAssignmentRoutes,
  handleRosterRoutes,
  handleTeacherAssignmentRoutes,
  handleAdmissionRoutes,
  handleManageAccountsRoutes,
  handleFeesRoutes,
  handleReportCardRoutes,
  handleCbtRoutes,
  handleAnnouncementRoutes,
  handleResultsRoutes,
  handleSiteContentRoutes,
  handleGalleryRoutes,
  handleBirthdayRoutes,
  handleAuditRoutes,
  handleSmsRoutes
];

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*", // tighten to your portal's domain before production
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
  };
}

// =====================================================================
// NIGHTLY D1 BACKUP -> TELEGRAM
// Runs from a Cron Trigger (see wrangler.toml). Asks Cloudflare to export
// the whole database as a .sql file, then sends that file to your Telegram
// bot chat. If anything fails, a short failure message is sent instead.
// Needs: vars ACCOUNT_ID, DATABASE_ID, TELEGRAM_CHAT_ID and the secrets
// D1_REST_API_TOKEN and TELEGRAM_BOT_TOKEN.
// =====================================================================
const TELEGRAM_MAX_BYTES = 45 * 1024 * 1024; // Telegram bots can upload up to 50 MB

function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function telegramSendMessage(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: String(text).slice(0, 3500) })
    });
  } catch (_) { /* nothing more we can do */ }
}

async function backupDatabaseToTelegram(env) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID || !env.D1_REST_API_TOKEN || !env.ACCOUNT_ID || !env.DATABASE_ID) {
    throw new Error("Backup is not configured: need TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, D1_REST_API_TOKEN, ACCOUNT_ID and DATABASE_ID.");
  }

  const url = `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/d1/database/${env.DATABASE_ID}/export`;
  const headers = {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${env.D1_REST_API_TOKEN}`
  };

  async function callExport(payload) {
    const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(payload) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) {
      throw new Error(`D1 export API error (${res.status}): ${JSON.stringify(data.errors || data).slice(0, 300)}`);
    }
    return data.result || {};
  }

  // 1) Start the export
  let result = await callExport({ output_format: "polling" });
  const bookmark = result.at_bookmark;
  if (!bookmark) throw new Error("Export did not return a bookmark.");

  // 2) Poll until the download link is ready (about 4 minutes at most)
  const pick = (r) => (r && r.result && r.result.signed_url ? r.result : r);
  let out = pick(result);
  for (let i = 0; i < 60 && !(out && out.signed_url); i++) {
    await sleepMs(4000);
    result = await callExport({ output_format: "polling", current_bookmark: bookmark });
    if (result.status === "error") throw new Error("D1 export failed: " + JSON.stringify(result.error || result.messages || "").slice(0, 300));
    out = pick(result);
  }
  if (!out || !out.signed_url) throw new Error("Export was not ready in time.");

  // 3) Download the .sql file
  const dump = await fetch(out.signed_url);
  if (!dump.ok) throw new Error("Could not download the export file (" + dump.status + ").");
  const bytes = await dump.arrayBuffer();
  if (bytes.byteLength < 100) throw new Error("Backup file looks empty.");

  const day = new Date().toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
  const filename = `fis-portal-db-${day}.sql`;
  const kb = Math.round(bytes.byteLength / 1024);

  if (bytes.byteLength > TELEGRAM_MAX_BYTES) {
    throw new Error(`Backup is ${kb} KB, too large to send on Telegram. Time to move to a bigger backup method.`);
  }

  // 4) Send it to Telegram
  const form = new FormData();
  form.append("chat_id", String(env.TELEGRAM_CHAT_ID));
  form.append("caption", `FIS Portal backup ${day} (${kb} KB)`);
  form.append("document", new Blob([bytes], { type: "application/sql" }), filename);

  const tgRes = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendDocument`, {
    method: "POST",
    body: form
  });
  const tgData = await tgRes.json().catch(() => ({}));
  if (!tgRes.ok || !tgData.ok) {
    throw new Error("Telegram rejected the backup: " + String(tgData.description || tgRes.status).slice(0, 200));
  }

  console.log(`Backup sent to Telegram: ${filename} (${kb} KB).`);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    const url = new URL(request.url);

    try {
      for (const handler of modules) {
        const response = await handler(request, env, url);
        if (response) {
          await recordAudit(request, env, url, response);
          const merged = new Headers(response.headers);
          for (const [k, v] of Object.entries(corsHeaders())) merged.set(k, v);
          return new Response(response.body, { status: response.status, headers: merged });
        }
      }
    } catch (err) {
      const message = String(err && err.message || err);
      let friendly = "Something went wrong while saving. Please try again.";

      if (message.includes("FOREIGN KEY")) {
        friendly = "Could not save — your account, or one of the records you selected (class, subject, or student), could not be verified. Please log out and log back in, then try again.";
      } else if (message.includes("UNIQUE")) {
        friendly = "That already exists — please check for a duplicate entry.";
      }

      return new Response(JSON.stringify({ error: friendly, detail: message }), {
        status: message.includes("FOREIGN KEY") ? 409 : 500,
        headers: { "Content-Type": "application/json", ...corsHeaders() }
      });
    }

    // No API module matched — serve the frontend (portal.html, via the
    // Worker's static assets binding) for anything that isn't an /api/ call.
    if (!url.pathname.startsWith("/api/") && env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(JSON.stringify({ error: "Not found." }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders() }
    });
  },

  // Runs on the Cron Trigger in wrangler.toml (nightly backup to Telegram)
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      backupDatabaseToTelegram(env).catch(async (err) => {
        const msg = String(err && err.message || err);
        console.error("Nightly backup FAILED:", msg);
        await telegramSendMessage(env, "FIS Portal nightly backup FAILED: " + msg);
        throw err;
      })
    );
  }
};
