import { timestamp, pgTable, text, boolean, pgEnum } from "drizzle-orm/pg-core";
import { projects } from "./projects.js";
import crypto from "crypto";

export const domainStateEnum = pgEnum("domainState", [
    "pending-analysis",
    "healthy",
    "burnt",
    "aging",
    "unhealthy",
    "archived",
]);

export const domains = pgTable("domains", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    projectId: text("projectId").references(() => projects.id, {
        onDelete: "cascade",
    }),
    domain: text("domain").notNull(),
    category: text("category").default("unknown"),
    // State is used to monitor whether or not the domain has been compromised & its health (e.g. enumerated by a SOC)
    state: domainStateEnum("state").notNull().default("pending-analysis"),
    stateUpdated: timestamp("stateUpdated"),
    stateAutoScan: boolean("stateAutoScan").default(true),
    dnsAutoScan: boolean("dnsAutoScan").default(true),
    description: text("description"),
    updated: timestamp("updated").defaultNow(),
});
