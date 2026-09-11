/**
 * FIS Itobe Portal — Worker route module (Auth & Account Approval)
 * Exported as a route handler, combined with other modules in index.js.
 *
 * Routes:
 *   POST /api/signup            { name, email, password, requestedRole, requestedLevel }
 *   POST /api/login             { email, password }
 *   GET  /api/approvals         (auth: admin) list pending users
 *   POST /api/approvals/:id     (auth: admin) { action: 'approve'|'reject', role, level }
 *   GET  /api/me                (auth: any staff) return current user profile
 */

import { hash, verify } from "./lib-password.js";
import { signToken } from "./lib-jwt.js";
import { getSession, isAdminSession } from "./lib-auth.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function uuid() {
  return crypto.randomUUID();
}

/**
 * Returns a Response if this module handles the request, or null to let
 * the router try the next module.
 */
export async function handleAuthRoutes(request, env, url) {
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
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

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
    if (!isAdminSession(sessionCtx)) return json({ error: "Not authorised." }, 403);

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
