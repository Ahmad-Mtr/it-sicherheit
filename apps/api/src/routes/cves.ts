import { Elysia, t } from "elysia";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { db, cve, cwe, cveCweMap } from "@vuln/db";
import { matchesVersionRange } from "@vuln/shared";
import { paginationQuery, paginationMeta } from "../pagination";
import { authGuard } from "../lib/auth";

async function loadCwesForCves(cveIds: string[]) {
  if (cveIds.length === 0) return new Map<string, { id: string; name: string }[]>();
  const rows = await db
    .select({ cveId: cveCweMap.cveId, id: cwe.id, name: cwe.name })
    .from(cveCweMap)
    .innerJoin(cwe, eq(cveCweMap.cweId, cwe.id))
    .where(inArray(cveCweMap.cveId, cveIds));

  const map = new Map<string, { id: string; name: string }[]>();
  for (const row of rows) {
    const list = map.get(row.cveId) ?? [];
    list.push({ id: row.id, name: row.name });
    map.set(row.cveId, list);
  }
  return map;
}

export const cvesRoutes = new Elysia({ prefix: "/api/cves" })
  .use(authGuard)
  .get(
    "/",
    async ({ query }) => {
      const limit = query.limit ?? 20;
      const offset = query.offset ?? 0;

      // affected_software is jsonb; filter product with a containment query,
      // then (optionally) narrow by version in application code since
      // versions are semver ranges, not exact values a SQL predicate can match.
      const productFilter = query.product
        ? sql`exists (
            select 1 from jsonb_array_elements(${cve.affectedSoftware}) as entry
            where lower(entry->>'product') = lower(${query.product})
          )`
        : sql`true`;

      const rows = await db
        .select()
        .from(cve)
        .where(and(productFilter))
        .orderBy(desc(cve.cvssScore))
        .limit(limit)
        .offset(offset);

      const filtered = query.version
        ? rows.filter((row) =>
            row.affectedSoftware.some(
              (entry) =>
                (!query.product || entry.product.toLowerCase() === query.product.toLowerCase()) &&
                entry.versions.some((range) => matchesVersionRange(query.version!, range)),
            ),
          )
        : rows;

      const countRows = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(cve)
        .where(and(productFilter));
      const count = countRows[0]!.count;

      const cweMap = await loadCwesForCves(filtered.map((r) => r.id));

      return {
        data: filtered.map((r) => ({ ...r, cwes: cweMap.get(r.id) ?? [] })),
        meta: paginationMeta(count, limit, offset),
      };
    },
    {
      query: t.Object({
        product: t.Optional(t.String()),
        version: t.Optional(t.String()),
        ...paginationQuery,
      }),
    },
  )
  .get(
    "/:id",
    async ({ params, status: sendStatus }) => {
      const [row] = await db.select().from(cve).where(eq(cve.id, params.id)).limit(1);
      if (!row) return sendStatus(404, { error: "CVE not found" });

      const cweMap = await loadCwesForCves([row.id]);
      return { ...row, cwes: cweMap.get(row.id) ?? [] };
    },
    { params: t.Object({ id: t.String() }) },
  )
  .delete(
    "/:id",
    async ({ params, requireRole, status: sendStatus }) => {
      const authError = requireRole("admin");
      if (authError) return sendStatus(authError.status, authError.body);

      const [deleted] = await db.delete(cve).where(eq(cve.id, params.id)).returning({ id: cve.id });
      if (!deleted) return sendStatus(404, { error: "CVE not found" });
      return { deleted: deleted.id };
    },
    { params: t.Object({ id: t.String() }) },
  );
