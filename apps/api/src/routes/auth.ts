import { Elysia, t } from "elysia";
import { eq } from "drizzle-orm";
import { db, user } from "@vuln/db";
import { jwtPlugin } from "../lib/auth";

export const authRoutes = new Elysia({ prefix: "/api/auth" })
  .use(jwtPlugin)
  .post(
    "/login",
    async ({ body, jwt, status: sendStatus }) => {
      const [row] = await db.select().from(user).where(eq(user.email, body.email)).limit(1);
      if (!row) return sendStatus(401, { error: "Invalid credentials" });

      const valid = await Bun.password.verify(body.password, row.passwordHash);
      if (!valid) return sendStatus(401, { error: "Invalid credentials" });

      const token = await jwt.sign({ sub: row.id, email: row.email, role: row.role });
      return { token, user: { id: row.id, email: row.email, role: row.role } };
    },
    {
      body: t.Object({
        email: t.String({ format: "email" }),
        password: t.String({ minLength: 1 }),
      }),
    },
  );
