import { Elysia, t } from "elysia";
import { desc, eq, sql } from "drizzle-orm";
import { db, cwe, cve, cveCweMap } from "@vuln/db";
import { paginationQuery, paginationMeta } from "../pagination";
import { authGuard } from "../lib/auth";

export const cwesRoutes = new Elysia({ prefix: "/api/cwes" })
  .use(authGuard)
  .get(
    "/:id/cves",
    async ({ params, query, status: sendStatus }) => {
      const [cweRow] = await db.select().from(cwe).where(eq(cwe.id, params.id)).limit(1);
      if (!cweRow) return sendStatus(404, { error: "CWE not found" });

      const limit = query.limit ?? 20;
      const offset = query.offset ?? 0;

      const rows = await db
        .select({ cve })
        .from(cveCweMap)
        .innerJoin(cve, eq(cveCweMap.cveId, cve.id))
        .where(eq(cveCweMap.cweId, params.id))
        .orderBy(desc(cve.cvssScore))
        .limit(limit)
        .offset(offset);

      const countRows = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(cveCweMap)
        .where(eq(cveCweMap.cweId, params.id));
      const count = countRows[0]!.count;

      return {
        cwe: cweRow,
        data: rows.map((r) => r.cve),
        meta: paginationMeta(count, limit, offset),
      };
    },
    {
      params: t.Object({ id: t.String() }),
      query: t.Object(paginationQuery),
    },
  )
  .delete(
    "/:id",
    async ({ params, requireRole, status: sendStatus }) => {
      const authError = requireRole("admin");
      if (authError) return sendStatus(authError.status, authError.body);

      const [deleted] = await db.delete(cwe).where(eq(cwe.id, params.id)).returning({ id: cwe.id });
      if (!deleted) return sendStatus(404, { error: "CWE not found" });
      return { deleted: deleted.id };
    },
    { params: t.Object({ id: t.String() }) },
  );
