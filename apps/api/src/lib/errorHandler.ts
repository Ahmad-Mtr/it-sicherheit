import { Elysia } from "elysia";
import { randomUUIDv7 } from "bun";

/**
 * A05: Security Misconfiguration — never leak internals (stack traces, SQL
 * errors, file paths) to the client. Every unhandled error gets a request ID
 * that correlates the generic client response with the full trace in server logs.
 */
export const errorHandler = new Elysia().onError({ as: "global" }, ({ code, error, set }) => {
  const requestId = randomUUIDv7();

  if (code === "VALIDATION") {
    set.status = 400;
    return { error: "Invalid request", requestId };
  }
  if (code === "NOT_FOUND") {
    set.status = 404;
    return { error: "Not found", requestId };
  }

  console.error(`[${requestId}]`, error);
  set.status = 500;
  return { error: "Internal server error", requestId };
});
