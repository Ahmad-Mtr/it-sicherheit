import { Elysia, t } from "elysia";
import { desc, eq, inArray, sql } from "drizzle-orm";
import { db, cve, cwe, cveCweMap } from "@vuln/db";
import { matchesVersionRange } from "@vuln/shared";
import { strictRateLimit } from "../lib/rateLimit";

type InventoryPackage = {
  name: string;
  version: string;
};

type MatchedPackage = InventoryPackage & {
  affectedRanges: string[];
};

type CweReport = {
  id: string;
  name: string;
  description: string;
  potentialImpact: string;
};

function normalizePackageName(name: string): string {
  return name.trim().toLowerCase();
}

function deduplicateInventory(packages: InventoryPackage[]): InventoryPackage[] {
  const uniquePackages = new Map<string, InventoryPackage>();

  for (const item of packages) {
    const normalized = {
      name: item.name.trim(),
      version: item.version.trim(),
    };
    const key = `${normalizePackageName(normalized.name)}\u0000${normalized.version}`;

    if (!uniquePackages.has(key)) {
      uniquePackages.set(key, normalized);
    }
  }

  return [...uniquePackages.values()];
}

async function loadCwesForCves(cveIds: string[]): Promise<Map<string, CweReport[]>> {
  if (cveIds.length === 0) return new Map();

  const rows = await db
    .select({
      cveId: cveCweMap.cveId,
      id: cwe.id,
      name: cwe.name,
      description: cwe.description,
      potentialImpact: cwe.potentialImpact,
    })
    .from(cveCweMap)
    .innerJoin(cwe, eq(cveCweMap.cweId, cwe.id))
    .where(inArray(cveCweMap.cveId, cveIds));

  const cwesByCve = new Map<string, CweReport[]>();

  for (const row of rows) {
    const linkedCwes = cwesByCve.get(row.cveId) ?? [];
    linkedCwes.push({
      id: row.id,
      name: row.name,
      description: row.description,
      potentialImpact: row.potentialImpact,
    });
    cwesByCve.set(row.cveId, linkedCwes);
  }

  return cwesByCve;
}

export const scanRoutes = new Elysia({ prefix: "/api/scan" })
  .use(strictRateLimit)
  .post(
    "/",
    async ({ body }) => {
      const inventory = deduplicateInventory(body.packages);
      const productNames = [
        ...new Set(inventory.map((item) => normalizePackageName(item.name))),
      ];

      // Restrict the database result to CVEs that mention at least one product
      // from the submitted inventory. Version ranges are evaluated below with
      // the shared semver-aware matcher.
      const productParameters = sql.join(
        productNames.map((productName) => sql`${productName}`),
        sql`, `,
      );

      const candidateCves = await db
        .select()
        .from(cve)
        .where(sql`exists (
          select 1
          from jsonb_array_elements(${cve.affectedSoftware}) as entry
          where lower(entry->>'product') in (${productParameters})
        )`)
        .orderBy(desc(cve.cvssScore));

      const findings = candidateCves.flatMap((candidate) => {
        const matchedPackages: MatchedPackage[] = [];

        for (const installedPackage of inventory) {
          const installedProduct = normalizePackageName(installedPackage.name);
          const affectedRanges: string[] = candidate.affectedSoftware
            .filter(
              (affectedEntry) =>
                normalizePackageName(affectedEntry.product) === installedProduct,
            )
            .flatMap((affectedEntry) =>
              affectedEntry.versions.filter((range) =>
                matchesVersionRange(installedPackage.version, range),
              ),
            );

          if (affectedRanges.length > 0) {
            matchedPackages.push({
              ...installedPackage,
              affectedRanges: [...new Set(affectedRanges)],
            });
          }
        }

        if (matchedPackages.length === 0) return [];

        return [
          {
            ...candidate,
            cvssScore: Number(candidate.cvssScore),
            matchedPackages,
          },
        ];
      });

      // PostgreSQL numeric values are returned as strings by the driver. Sort
      // explicitly as numbers so 10.0 is correctly ranked above 9.8.
      findings.sort(
        (left, right) =>
          right.cvssScore - left.cvssScore || left.id.localeCompare(right.id),
      );

      const cwesByCve = await loadCwesForCves(findings.map((finding) => finding.id));
      const vulnerablePackageKeys = new Set(
        findings.flatMap((finding) =>
          finding.matchedPackages.map(
            (item) => `${normalizePackageName(item.name)}\u0000${item.version}`,
          ),
        ),
      );

      return {
        data: findings.map((finding) => ({
          ...finding,
          cwes: cwesByCve.get(finding.id) ?? [],
        })),
        meta: {
          submittedPackages: body.packages.length,
          scannedPackages: inventory.length,
          vulnerablePackages: vulnerablePackageKeys.size,
          vulnerabilitiesFound: findings.length,
        },
      };
    },
    {
      body: t.Object({
        packages: t.Array(
          t.Object({
            name: t.String({ minLength: 1, maxLength: 255 }),
            version: t.String({ minLength: 1, maxLength: 100 }),
          }),
          { minItems: 1, maxItems: 1000 },
        ),
      }),
    },
  );
