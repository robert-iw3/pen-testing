import { pgTable, text } from "drizzle-orm/pg-core";

export const settings = pgTable("settings", {
    name: text("name").unique().primaryKey(),
    value: text("value").notNull(),
});
