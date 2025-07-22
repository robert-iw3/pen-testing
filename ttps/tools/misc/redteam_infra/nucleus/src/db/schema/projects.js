import { pgTable, text, date, pgEnum } from "drizzle-orm/pg-core";
import crypto from "crypto";

export const projectStatusEnum = pgEnum("projectStatus", [
  "not-started",
  "in-progress",
  "done",
  "delayed",
]);

export const projects = pgTable("projects", {
  id: text("id")
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  name: text("name").notNull(),
  status: projectStatusEnum("status").default("not-started").notNull(),
  startDate: date("startDate"),
  endDate: date("endDate"),
});
