import { pgTable, text, json } from "drizzle-orm/pg-core";
import { encryptedText } from "../../lib/crypto.js";
import crypto from "crypto";

export const files = pgTable("files", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    name: text("name").notNull(),
    extension: text("extension").notNull(),
    value: encryptedText("value").notNull(),
    variables: json("variables").array(),
});
