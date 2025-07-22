import { pgTable, text, pgEnum, json } from "drizzle-orm/pg-core";
import crypto from "crypto";
import { deployments } from "./deployments.js";
import { templates } from "./templates.js";

export const infrastructureStatusEnum = pgEnum("infrastructureStatus", [
    "pending",
    "building",
    "configuring",
    "default",
    "failed",
    "running",
]);

export const infrastructure = pgTable("infrastructure", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    deploymentId: text("deploymentId").references(() => deployments.id, {
        onDelete: "cascade",
    }),
    name: text("name").notNull(),
    infrastructureTemplateId: text("infrastructureTemplateId").references(
        () => templates.id,
        {
            onDelete: "no action",
        },
    ),
    configurations: json("configurations").array(),
    deployedConfigurations: json("deployedConfigurations").array(),
    status: infrastructureStatusEnum("status").notNull().default("pending"),
    description: text("description"),
    username: text("username"),
});
