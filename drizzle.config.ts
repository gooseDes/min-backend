import { defineConfig } from "drizzle-kit";

export default defineConfig({
    schema: "./src/db/schema.ts",
    out: "./drizzle",
    dialect: "mysql",
    dbCredentials: {
        host: process.env.DB_HOST || "localhost",
        user: "root",
        password: "root",
        database: "min",
    },
});
