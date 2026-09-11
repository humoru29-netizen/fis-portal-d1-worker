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
 */

import { verify as verifyPin } from "./lib-password.js"; // same PBKDF2 verify, PINs hashed the same way
import { signToken } from "./lib-jwt.js";
import { getSession } from "./lib-auth.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

export async function handleStudentAuthRoutes(request, env, url) {
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

      const valid = await verifyPin(pin, pinRow.pin_hash);
      if (!valid) {
        return json({ error: "Incorrect PIN." }, 401);
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
          level: student.level
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
        classId: s.class_id, level: s.level
      });
    }

    return null; // not handled here — let the router try the next module
}
