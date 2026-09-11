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

import { getSession, isTeachingStaff, isOwnStudent } from "./lib-auth.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function uuid() {
  return crypto.randomUUID();
}

const VALID_STATUSES = ["present", "absent", "late", "excused"];

export async function handleAttendanceRoutes(request, env, url) {
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

      // Upsert each record — one row per student per date (see UNIQUE constraint)
      const statements = records.map(r =>
        env.DB.prepare(
          `INSERT INTO attendance (id, student_id, class_id, date, status, term, session, marked_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(student_id, date) DO UPDATE SET
             status = excluded.status,
             marked_by = excluded.marked_by,
             marked_at = datetime('now')`
        ).bind(uuid(), r.studentId, classId, date, r.status, term, session, sessionCtx.id)
      );

      await env.DB.batch(statements);
      return json({ message: `Attendance saved for ${records.length} student(s).` });
    }

    // ---------------- VIEW ONE DAY FOR A CLASS ----------------
    if (pathname === "/api/attendance" && request.method === "GET") {
      const sessionCtx = await getSession(request, env);
      if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

      const classId = url.searchParams.get("classId");
      const date = url.searchParams.get("date");
      if (!classId || !date) return json({ error: "classId and date are required." }, 400);

      const { results } = await env.DB
        .prepare(
          `SELECT a.student_id, s.name AS student_name, a.status
           FROM students s
           LEFT JOIN attendance a ON a.student_id = s.id AND a.date = ?
           WHERE s.class_id = ? AND s.status = 'active'
           ORDER BY s.name`
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
           ORDER BY s.name`
        )
        .bind(term, session, classId)
        .all();

      return json({ classId, term, session, summary: results });
    }

    return null; // not handled here — let the router try the next module
}
