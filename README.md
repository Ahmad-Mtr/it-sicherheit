# Vulnerability Management System

CVE/CWE tracking and import — Bun + Elysia API backed by local Postgres via Drizzle.

For step-by-step setup, an endpoint reference, testing commands, and troubleshooting, see **[SETUP.md](SETUP.md)**.

## Prerequisites

- [Bun](https://bun.sh) 1.3+
- Docker (for local Postgres)

## Setup

```bash
bun install
cp .env.example .env      # defaults already point at the docker-compose db
docker compose up -d      # Postgres on localhost:5433

bun run db:generate       # generate SQL migrations from packages/db/src/schema.ts
bun run db:migrate        # apply migrations
bun run db:seed           # seed 30 CWEs, 55 CVEs, and two accounts
```

Seeded accounts (printed again at the end of `db:seed`):

- `admin@example.com` / `Admin123!` (admin — can delete CVEs/CWEs)
- `user@example.com` / `User123!` (user — can import)

## Running

```bash
bun run dev:api   # http://localhost:3001  (Swagger docs at /docs)
```

## Repo layout

```
/apps
  /api        Elysia server (src/index.ts)
/packages
  /db         drizzle schema, migrations, seed script
  /shared     shared types + version-matching logic
docker-compose.yml
```
