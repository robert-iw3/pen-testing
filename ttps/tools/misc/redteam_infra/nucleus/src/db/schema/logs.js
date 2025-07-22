import { pgTable, text, pgEnum, timestamp } from "drizzle-orm/pg-core";
import { projects } from "./projects.js";
import crypto from "crypto";

export const logStatusEnum = pgEnum("logStatus", [
    "info",
    "warning",
    "error",
    "unknown",
]);

// TODO: Change/refine these
export const logSourceEnum = pgEnum("logSource", [
    "postgres",
    "nucleus",
    "radar",
    "command",
    "tailscale",
    "terraform",
    "ansible",
]);

export const logs = pgTable("logs", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    message: text("message").notNull(),
    source: logSourceEnum("source").notNull(),
    status: logStatusEnum("status").notNull(),
    timestamp: timestamp({ mode: "date", withTimezone: true }).defaultNow(),
    resource: text("resource"),
    projectId: text("projectId").references(() => projects.id, {
        onDelete: "cascade",
    }),
});
