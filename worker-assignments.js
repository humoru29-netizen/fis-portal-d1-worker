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
 */

import { getSession, isTeachingStaff } from "./lib-auth.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function uuid() {
  return crypto.randomUUID();
}

const SUBMISSION_STATUSES = ["not_submitted", "submitted", "late", "graded"];

export async function handleAssignmentRoutes(request, env, url) {
  const { pathname } = url;

  // ---------------- CREATE ASSIGNMENT ----------------
  if (pathname === "/api/assignments" && request.method === "POST") {
    const sessionCtx = await getSession(request, env);
    if (!isTeachingStaff(sessionCtx)) return json({ error: "Not authorised." }, 403);

    const { title, description, classId, subjectId, dueDate, term, session } = await request.json();
    if (!title || !classId || !subjectId || !dueDate || !term || !session) {
      return json({ error: "title, classId, subjectId, dueDate, term, and session are required." }, 400);
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
    const due = new Date(assignment.due_date);
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

    const { results } = await env.DB
      .prepare(
        `SELECT s.id AS student_id, s.name,
                COALESCE(sub.status, 'not_submitted') AS status,
                sub.submitted_at, sub.remark
         FROM students s
         LEFT JOIN assignment_submissions sub
           ON sub.student_id = s.id AND sub.assignment_id = ?
         WHERE s.class_id = ? AND s.status = 'active'
         ORDER BY s.name`
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

  return null; // not handled here — let the router try the next module
}
