/**
 * Shared session helper — used by every Worker route file.
 * Two kinds of session token, distinguished by payload.type:
 *   'staff'   -> sub = users.id      (password login)
 *   'student' -> sub = students.id   (admission no + PIN login)
 */

import { verifyToken } from "./lib-jwt.js";

export async function getSession(request, env) {
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

export function isStaff(session) {
  return !!session && session.type === "staff";
}

export function isAdminSession(session) {
  return isStaff(session) && ["general_admin", "primary_admin", "secondary_admin"].includes(session.role);
}

export function isTeachingStaff(session) {
  return isStaff(session) && ["general_admin", "primary_admin", "secondary_admin", "teacher"].includes(session.role);
}

export function isOwnStudent(session, studentId) {
  return !!session && session.type === "student" && session.id === studentId;
}
