import express, { type Express } from "express";
import fs from "fs";
import path from "path";
import { createServer as createViteServer, createLogger } from "vite";
import { type Server } from "http";
import { nanoid } from "nanoid";

const viteLogger = createLogger();

export async function setupAdminVite(app: Express, server: Server) {
  const adminVite = await createViteServer({
    root: path.resolve(import.meta.dirname, "..", "apps", "admin"),
    base: "/admin/",
    configFile: path.resolve(import.meta.dirname, "..", "apps", "admin", "vite.config.ts"),
    server: {
      middlewareMode: true,
      hmr: { server },
      allowedHosts: true as const,
    },
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      },
    },
    appType: "custom",
  });

  // Mount admin app at /admin
  app.use("/admin", adminVite.middlewares);
  
  // Serve admin app for /admin/* routes
  app.get("/admin*", async (req, res, next) => {
    const url = req.originalUrl;

    try {
      const adminTemplate = path.resolve(
        import.meta.dirname,
        "..",
        "apps",
        "admin",
        "index.html",
      );

      // always reload the index.html file from disk incase it changes
      let template = await fs.promises.readFile(adminTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`,
      );
      const page = await adminVite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      adminVite.ssrFixStacktrace(e as Error);
      next(e);
    }
  });
}

export function serveAdminStatic(app: Express) {
  const adminDistPath = path.resolve(import.meta.dirname, "..", "apps", "admin", "dist");

  if (!fs.existsSync(adminDistPath)) {
    throw new Error(
      `Could not find the admin build directory: ${adminDistPath}, make sure to build the admin app first`,
    );
  }

  // Serve admin static files at /admin
  app.use("/admin", express.static(adminDistPath));

  // Fall through to admin index.html for /admin/* routes
  app.get("/admin*", (_req, res) => {
    res.sendFile(path.resolve(adminDistPath, "index.html"));
  });
}