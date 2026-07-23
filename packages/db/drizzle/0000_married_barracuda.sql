CREATE TABLE IF NOT EXISTS "cve" (
	"id" varchar(32) PRIMARY KEY NOT NULL,
	"description" text NOT NULL,
	"affected_software" jsonb NOT NULL,
	"cvss_score" numeric(3, 1) NOT NULL,
	"published_date" date NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "cve_cwe_map" (
	"cve_id" varchar(32) NOT NULL,
	"cwe_id" varchar(16) NOT NULL,
	CONSTRAINT "cve_cwe_map_cve_id_cwe_id_pk" PRIMARY KEY("cve_id","cwe_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "cwe" (
	"id" varchar(16) PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"potential_impact" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "user" (
	"id" text PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"password_hash" text NOT NULL,
	"role" varchar(8) DEFAULT 'user' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "user_email_unique" UNIQUE("email")
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "cve_cwe_map" ADD CONSTRAINT "cve_cwe_map_cve_id_cve_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cve"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "cve_cwe_map" ADD CONSTRAINT "cve_cwe_map_cwe_id_cwe_id_fk" FOREIGN KEY ("cwe_id") REFERENCES "public"."cwe"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
