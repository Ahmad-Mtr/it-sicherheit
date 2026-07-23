# Setup & Testing Guide

Local CVE/CWE vulnerability-tracking backend: an **Elysia API** (Bun) over a
**PostgreSQL** database managed with **Drizzle**. Everything runs locally.

Module A + C are implemented here. Module B is to be implemented

---

## 1. Prerequisites

| Tool | Version | Install |
|---|---|---|
| Bun | ≥ 1.3 | `curl -fsSL https://bun.sh/install \| bash` |
| Docker + Compose | any recent | https://docs.docker.com/get-docker/ |

## 2. Setup

Run from the repo root:

```bash
bun install                 # install deps

cp .env.example .env        # defaults already point at the docker db, so no need to change anything since its local

docker compose up -d        # Postgres on localhost:5433

bun run db:generate         # generate SQL migration from packages/db/src/schema.ts
bun run db:migrate          # apply migration to the database
bun run db:seed             # seed data, seed.ts
```

`db:seed` prints the two seeded logins when it finishes:

| Email | Password | Role | Permissions |
|---|---|---|---|
| `admin@example.com` | `Admin123!` | admin | import + **delete** |
| `user@example.com` | `User123!` | user | import |

> The `db:*` scripts and the API load environment variables from the root
> `.env` via `--env-file`, so they work regardless of which subdirectory the
> underlying command runs in.

## 3. Run

```bash
bun run dev:api    # http://localhost:3001  (auto-reloads on change)
```

- Interactive API docs (Swagger — try requests in the browser): **http://localhost:3001/docs**
- Health check: **http://localhost:3001/health**

Stop it with `Ctrl-C`. (See Troubleshooting if the port stays busy.)

---

## 4. API reference

Base URL: `http://localhost:3001/docs`

## 5. Testing (curl)

Read endpoints are public; import needs a token; delete needs an **admin** token.

```bash
B=localhost:3001

# --- public reads ---
curl $B/health
curl "$B/api/cves?limit=5"
curl "$B/api/cves?product=lodash&version=4.17.20"   # semver-range match
curl $B/api/cves/CVE-2023-10001                     # single CVE + linked CWEs
curl "$B/api/cwes/CWE-79/cves?limit=5"              # CVEs for a CWE

# --- log in, capture a token (needs jq) ---
ADMIN=$(curl -s $B/api/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"Admin123!"}' | jq -r .token)
USER=$(curl -s $B/api/auth/login -H 'content-type: application/json' \
  -d '{"email":"user@example.com","password":"User123!"}' | jq -r .token)

# --- import (auth required) ---
curl $B/api/import/cwe -H "authorization: Bearer $USER" -H 'content-type: application/json' \
  -d '[{"id":"CWE-999","name":"Test","description":"demo","potentialImpact":"none"}]'

curl $B/api/import/cve -H "authorization: Bearer $USER" -H 'content-type: application/json' \
  -d '[{"id":"CVE-2024-99999","description":"demo","affectedSoftware":[{"product":"demolib","versions":["<1.2.3"]}],"cvssScore":7.5,"publishedDate":"2024-01-01","cweIds":["CWE-999"]}]'

# the imported CVE is now searchable
curl "$B/api/cves?product=demolib&version=1.0.0"

# --- delete (admin only) ---
curl -X DELETE $B/api/cves/CVE-2024-99999 -H "authorization: Bearer $ADMIN"
curl -X DELETE $B/api/cwes/CWE-999        -H "authorization: Bearer $ADMIN"
```

## 6. Reset / teardown

```bash
docker compose down          # stop Postgres (keeps data)
docker compose down -v       # stop + wipe data; re-run migrate + seed afterward
```

To re-seed a clean database:

```bash
docker compose down -v && docker compose up -d
bun run db:migrate && bun run db:seed
```

---

## 7. Troubleshooting

**`error: DATABASE_URL is not set`**
Make sure you copied `.env.example` to `.env`. The scripts read the root
`.env` — if you renamed or moved it, restore it at the repo root.

**Port 3001 already in use / rate limits behaving oddly**
Bun enables `SO_REUSEPORT` on Linux, so a *second* server started on the same
port silently shares it (the kernel load-balances between them, and each keeps
its own in-memory rate-limit counter). If a previous `dev:api` was left running,
a new one won't error — it just co-exists. Find and stop strays:

```bash
ss -ltnp | grep ':3001'      # list every process listening on 3001
kill <pid>                   # stop the stale one(s)
```

**Postgres connection refused**
`docker compose ps` should show the `postgres` service `healthy`. If it just
started, give it a few seconds. The DB listens on host port **5433** (not the
default 5432), which matches `DATABASE_URL` in `.env`.

**`db:migrate` says relation/schema "already exists, skipping"**
Harmless — those are Postgres `NOTICE` lines from re-running migrations against
an already-migrated database. Migrations are idempotent.
