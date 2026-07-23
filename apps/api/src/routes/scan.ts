import { Elysia, t } from "elysia";
import { strictRateLimit } from "../lib/rateLimit";

export const scanRoutes = new Elysia({ prefix: "/api/scan" })
  .use(strictRateLimit)
  .post(
    "/",
    ({ body, status }) => {
      // TODO(module-b): implement the scanner here.
      // `body` is the validated { packages: [{ name, version }] }.
      // See routes/cves.ts for Drizzle query patterns and use
      // matchesVersionRange() from @vuln/shared to match versions.
      return status(501, { error: "Scanner not implemented yet" });
    },
    {
      body: t.Object({
        packages: t.Array(
          t.Object({
            name: t.String(),
            version: t.String(),
          }),
          { minItems: 1, maxItems: 1000 },
        ),
      }),
    },
  );
