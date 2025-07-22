import { pgTable, text, pgEnum } from "drizzle-orm/pg-core";
import { encryptedText } from "../../lib/crypto.js";
import { getTableColumns } from "drizzle-orm";
import crypto from "crypto";

export const integrationPlatformEnum = pgEnum("integrationType", [
    "aws",
    "digitalocean",
    "tailscale",
]);

export const integrations = pgTable("integrations", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    platform: integrationPlatformEnum("platform").notNull(),
    name: text("name").notNull(),
    keyId: encryptedText("keyId"),
    secretKey: encryptedText("secretKey").notNull(),
});

const { keyId, secretKey, ...integrationSafeSelect } =
    getTableColumns(integrations);
export { integrationSafeSelect };
