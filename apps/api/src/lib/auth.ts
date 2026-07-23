import { Elysia } from "elysia";
import { jwt } from "@elysiajs/jwt";
import type { JwtPayload, Role } from "@vuln/shared";

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error("JWT_SECRET is not set");
}

export const jwtPlugin = new Elysia().use(
  jwt({
    name: "jwt",
    secret: jwtSecret,
    exp: "2h",
  }),
);

interface AuthError {
  status: 401 | 403;
  body: { error: string };
}

/**
 * Reads the Bearer token, verifies it, and decorates the context with
 * `requireAuth()` / `requireRole(role)` guard functions that routes call
 * explicitly and return the error from if present (A01: Broken Access Control).
 */
export const authGuard = new Elysia()
  .use(jwtPlugin)
  .derive({ as: "scoped" }, async ({ jwt, headers }) => {
    const authHeader = headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
    const payload = token ? ((await jwt.verify(token)) as JwtPayload | false) : false;

    return {
      currentUser: payload || null,
      requireAuth(): AuthError | null {
        if (!payload) return { status: 401, body: { error: "Authentication required" } };
        return null;
      },
      requireRole(role: Role): AuthError | null {
        if (!payload) return { status: 401, body: { error: "Authentication required" } };
        if (payload.role !== role) return { status: 403, body: { error: "Insufficient permissions" } };
        return null;
      },
    };
  });
