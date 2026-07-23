import { Elysia, t } from "elysia";
import { sql } from "drizzle-orm";
import { db, cve, cwe, cveCweMap } from "@vuln/db";
import { authGuard } from "../lib/auth";
import { strictRateLimit } from "../lib/rateLimit";

// drizzle helper for referencing the EXCLUDED pseudo-table in upserts
function sql_excluded(column: string) {
  return sql.raw(`excluded.${column}`);
}

const affectedSoftwareSchema = t.Array(
  t.Object({
    product: t.String(),
    versions: t.Array(t.String()),
  }),
);

const cveImportSchema = t.Object({
  id: t.String({ pattern: "^CVE-\\d{4}-\\d{4,}$" }),
  description: t.String(),
  affectedSoftware: affectedSoftwareSchema,
  cvssScore: t.Number({ minimum: 0, maximum: 10 }),
  publishedDate: t.String({ format: "date" }),
  cweIds: t.Optional(t.Array(t.String())),
});

const cweImportSchema = t.Object({
  id: t.String({ pattern: "^CWE-\\d+$" }),
  name: t.String(),
  description: t.String(),
  potentialImpact: t.String(),
});

export const importRoutes = new Elysia({ prefix: "/api/import" })
  .use(strictRateLimit)
  .use(authGuard)
  .post(
    "/cve",
    async ({ body, requireAuth, status: sendStatus }) => {
      const authError = requireAuth();
      if (authError) return sendStatus(authError.status, authError.body);

      const inserted = await db
        .insert(cve)
        .values(
          body.map((c) => ({
            id: c.id,
            description: c.description,
            affectedSoftware: c.affectedSoftware,
            cvssScore: String(c.cvssScore),
            publishedDate: c.publishedDate,
          })),
        )
        .onConflictDoUpdate({
          target: cve.id,
          set: {
            description: sql_excluded("description"),
            affectedSoftware: sql_excluded("affected_software"),
            cvssScore: sql_excluded("cvss_score"),
            publishedDate: sql_excluded("published_date"),
          },
        })
        .returning({ id: cve.id });

      const mappings = body.flatMap((c) =>
        (c.cweIds ?? []).map((cweId) => ({ cveId: c.id, cweId })),
      );
      if (mappings.length > 0) {
        await db.insert(cveCweMap).values(mappings).onConflictDoNothing();
      }

      return { imported: inserted.length };
    },
    { body: t.Array(cveImportSchema, { minItems: 1, maxItems: 500 }) },
  )
  .post(
    "/cwe",
    async ({ body, requireAuth, status: sendStatus }) => {
      const authError = requireAuth();
      if (authError) return sendStatus(authError.status, authError.body);

      const inserted = await db
        .insert(cwe)
        .values(body)
        .onConflictDoUpdate({
          target: cwe.id,
          set: {
            name: sql_excluded("name"),
            description: sql_excluded("description"),
            potentialImpact: sql_excluded("potential_impact"),
          },
        })
        .returning({ id: cwe.id });

      return { imported: inserted.length };
    },
    { body: t.Array(cweImportSchema, { minItems: 1, maxItems: 500 }) },
  );
