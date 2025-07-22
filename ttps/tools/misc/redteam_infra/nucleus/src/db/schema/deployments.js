import { pgTable, text, pgEnum } from "drizzle-orm/pg-core";
import { sshKeys } from "./sshKeys.js";
import { projects } from "./projects.js";
import { integrations } from "./integrations.js";
import crypto from "crypto";

export const deploymentStatusEnum = pgEnum("deploymentStatus", [
  "destroying",
  "ready-to-prepare",
  "preparing",
  "ready-to-deploy",
  "deploying",
  "ready-to-configure",
  "configuring",
  "live",
  "failed",
  "destroyed",
]);

export const deployments = pgTable("deployments", {
  id: text("id")
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  name: text("name").notNull(),
  description: text("description"),
  sshKeyId: text("sshKeyId")
    .references(() => sshKeys.id, {
      onDelete: "no action",
    })
    .notNull(),
  platformId: text("platformId")
    .references(() => integrations.id, {
      onDelete: "no action",
    })
    .notNull(),
  tailscaleId: text("tailscaleId")
    .references(() => integrations.id, {
      onDelete: "no action",
    })
    .notNull(),
  status: deploymentStatusEnum("status").default("ready-to-prepare").notNull(),
  projectId: text("projectId")
    .references(() => projects.id, {
      onDelete: "no action",
    })
    .notNull(),
  region: text("region").notNull(),
  log: text("log"),
});
