import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "@tullab/shared/schemas";

neonConfig.webSocketConstructor = ws;

// Make database optional for development
let db: ReturnType<typeof drizzle> | null = null;
let pool: Pool | null = null;

if (process.env.DATABASE_URL) {
  try {
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
    db = drizzle({ client: pool, schema });
    console.log("✅ Database connection configured");
  } catch (error) {
    console.warn("⚠️ Database connection failed, falling back to memory storage:", error);
  }
} else {
  console.log("ℹ️ No DATABASE_URL provided, using memory storage for development");
}

export { db, pool };
