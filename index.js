/**
 * FIS Itobe Portal — Worker entry point.
 * This is the ONE file Cloudflare actually deploys as the Worker
 * (set as `main` in wrangler.toml). Everything else is a route module
 * that returns a Response if it handles the request, or null to pass
 * through to the next module.
 *
 * To add a new feature (assignments, notes, etc.), write it the same way
 * as handleAttendanceRoutes and add one line to the `modules` array below.
 */

import { handleAuthRoutes } from "./worker-auth.js";
import { handleStudentAuthRoutes } from "./worker-student-login.js";
import { handleAttendanceRoutes } from "./worker-attendance.js";
import { handleAssignmentRoutes } from "./worker-assignments.js";

const modules = [
  handleAuthRoutes,
  handleStudentAuthRoutes,
  handleAttendanceRoutes,
  handleAssignmentRoutes
];

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*", // tighten to your portal's domain before production
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
  };
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
          // Attach CORS headers to whatever the module returned
          const merged = new Headers(response.headers);
          for (const [k, v] of Object.entries(corsHeaders())) merged.set(k, v);
          return new Response(response.body, { status: response.status, headers: merged });
        }
      }
    } catch (err) {
      return new Response(JSON.stringify({ error: "Internal error: " + err.message }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders() }
      });
    }

    return new Response(JSON.stringify({ error: "Not found." }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders() }
    });
  }
};
