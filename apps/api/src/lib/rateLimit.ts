import { rateLimit } from "elysia-rate-limit";
import type { Elysia } from "elysia";

type Server = NonNullable<Elysia["server"]>;

// The rate-limit plugin resolves the client IP via `app.server`, but plugin
// sub-apps never call `.listen()` themselves — only the root app does. This
// holder is populated from index.ts right after `.listen()` so both limiter
// instances can key their buckets by real client IP instead of falling back
// to a single shared bucket.
let runningServer: Server | null = null;
export function setRateLimitServer(server: Server | null) {
  runningServer = server;
}

const tooManyRequests = () =>
  new Response(JSON.stringify({ error: "Too many requests" }), {
    status: 429,
    headers: { "content-type": "application/json" },
  });

// A04: Insecure Design / Rate Limiting — baseline limiter applied to every
// route (per source IP), with a stricter limiter layered on top of
// /import since those endpoints do the most work per request.
export const globalRateLimit = rateLimit({
  duration: 60_000,
  max: 100,
  injectServer: () => runningServer,
  errorResponse: tooManyRequests(),
});

export const strictRateLimit = rateLimit({
  duration: 60_000,
  max: 10,
  scoping: "scoped",
  injectServer: () => runningServer,
  errorResponse: tooManyRequests(),
});
