import { pgTable, text } from "drizzle-orm/pg-core";
import { encryptedText } from "../../lib/crypto.js";
import crypto from "crypto";

export const sshKeys = pgTable("sshKeys", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    name: text("name").notNull(),
    public: encryptedText("public").notNull(),
    private: encryptedText("private").notNull(),
});
