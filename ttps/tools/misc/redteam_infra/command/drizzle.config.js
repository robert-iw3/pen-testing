import { defineConfig } from "drizzle-kit";

export default defineConfig({
  schema: "./src/lib/schema",
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url: `postgres://${process.env.POSTGRES_USER}:${process.env.POSTGRES_PASSWORD}@${process.env.POSTGRES_HOST}:5432/${process.env.POSTGRES_DB}`,
  },
});
