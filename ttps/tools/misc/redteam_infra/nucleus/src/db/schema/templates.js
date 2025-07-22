import { pgTable, text, pgEnum, json } from "drizzle-orm/pg-core";
import { encryptedText } from "../../lib/crypto.js";
import crypto from "crypto";

export const templateTypeEnum = pgEnum("templateType", [
  "infrastructure",
  "configuration",
]);

export const platformTypeEnum = pgEnum("platformType", ["aws", "digitalocean"]);

export const templates = pgTable("templates", {
  id: text("id")
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  name: text("name").notNull().unique(),
  value: encryptedText("value").notNull(),
  type: templateTypeEnum("type").notNull(),
  variables: json("variables").array(),
  platform: platformTypeEnum("platform"),
});
