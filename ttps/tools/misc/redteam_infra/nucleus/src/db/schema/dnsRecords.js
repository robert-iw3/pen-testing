import { timestamp, pgTable, text, pgEnum } from "drizzle-orm/pg-core";
import { domains } from "./domains.js";
import crypto from "crypto";

export const dnsRecordTypeEnum = pgEnum("dnsRecordType", [
    "a",
    "aaaa",
    "cname",
    "mx",
    "ns",
    "ptr",
    "soa",
    "srv",
    "txt",
]);

export const dnsRecords = pgTable("dnsRecords", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    type: dnsRecordTypeEnum("type").notNull(),
    name: text("name").notNull(),
    value: text("value"),
    domainId: text("domainId").references(() => domains.id, {
        onDelete: "cascade",
    }),
    updated: timestamp("updated").defaultNow(),
});
