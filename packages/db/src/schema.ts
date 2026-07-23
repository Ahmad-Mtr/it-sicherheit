import {
  pgTable,
  text,
  varchar,
  numeric,
  date,
  jsonb,
  primaryKey,
  timestamp,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import type { AffectedSoftwareEntry } from "@vuln/shared";

export const cwe = pgTable("cwe", {
  id: varchar("id", { length: 16 }).primaryKey(), // e.g. CWE-89
  name: text("name").notNull(),
  description: text("description").notNull(),
  potentialImpact: text("potential_impact").notNull(),
});

export const cve = pgTable("cve", {
  id: varchar("id", { length: 32 }).primaryKey(), // e.g. CVE-2024-12345
  description: text("description").notNull(),
  affectedSoftware: jsonb("affected_software")
    .$type<AffectedSoftwareEntry[]>()
    .notNull(),
  cvssScore: numeric("cvss_score", { precision: 3, scale: 1 }).notNull(),
  publishedDate: date("published_date").notNull(),
});

export const cveCweMap = pgTable(
  "cve_cwe_map",
  {
    cveId: varchar("cve_id", { length: 32 })
      .notNull()
      .references(() => cve.id, { onDelete: "cascade" }),
    cweId: varchar("cwe_id", { length: 16 })
      .notNull()
      .references(() => cwe.id, { onDelete: "cascade" }),
  },
  (table) => [primaryKey({ columns: [table.cveId, table.cweId] })],
);

// Auth: not specified in the schema section of the spec, but required to
// back the JWT login flow (A01) and the /login UI. Minimal user table.
export const user = pgTable("user", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: varchar("role", { length: 8, enum: ["user", "admin"] })
    .notNull()
    .default("user"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const cveRelations = relations(cve, ({ many }) => ({
  cweLinks: many(cveCweMap),
}));

export const cweRelations = relations(cwe, ({ many }) => ({
  cveLinks: many(cveCweMap),
}));

export const cveCweMapRelations = relations(cveCweMap, ({ one }) => ({
  cve: one(cve, { fields: [cveCweMap.cveId], references: [cve.id] }),
  cwe: one(cwe, { fields: [cveCweMap.cweId], references: [cwe.id] }),
}));
