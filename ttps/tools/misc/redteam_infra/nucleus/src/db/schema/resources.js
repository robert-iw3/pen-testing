import { pgTable, text } from "drizzle-orm/pg-core";
import crypto from "crypto";
import { infrastructure } from "./infrastructure.js";

export const resources = pgTable("resources", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    infrastructureId: text("infrastructureId").references(
        () => infrastructure.id,
        {
            onDelete: "cascade",
        },
    ),
    resourceType: text("resourceType"),
    resourceName: text("resourceName"),
    providerId: text("providerId"),
    publicIp: text("publicIp"),
    privateIp: text("privateIp"),
    tailscaleIp: text("tailscaleIp"),
});
