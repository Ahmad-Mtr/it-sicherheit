import { Elysia } from "elysia";
import { swagger } from "@elysiajs/swagger";
import { cors } from "@elysiajs/cors";
import { errorHandler } from "./lib/errorHandler";
import { globalRateLimit, setRateLimitServer } from "./lib/rateLimit";
import { authRoutes } from "./routes/auth";
import { cvesRoutes } from "./routes/cves";
import { cwesRoutes } from "./routes/cwes";
import { importRoutes } from "./routes/import";
import { scanRoutes } from "./routes/scan"; 

const app = new Elysia()
  .use(errorHandler)
  .use(cors())
  .use(
    swagger({
      path: "/docs",
      documentation: {
        info: {
          title: "Batata API || Todo: Besser Name bitte",
          version: "1.0.0",
          description: "CVE/CWE tracking and import API.",
        },
      },
    }),
  )
  .use(globalRateLimit)
  .use(authRoutes)
  .use(cvesRoutes)
  .use(cwesRoutes)
  .use(importRoutes)
  .use(scanRoutes)
  .get("/health", () => ({ status: "ok" }))
  .listen(process.env.PORT ? Number(process.env.PORT) : 3000);

setRateLimitServer(app.server);

console.log(`API listening at http://${app.server?.hostname}:${app.server?.port}`);
console.log(`Swagger docs at http://${app.server?.hostname}:${app.server?.port}/docs`);
