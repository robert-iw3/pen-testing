import { db } from "../db/index.js";
import { logs } from "../db/schema/logs.js";
import { desc, eq } from "drizzle-orm";

export const allLogs = async (req, res) => {
    const { projectId } = req.query;

    var rows = [];

    // TODO: How many to return? Should use time range
    if (projectId) {
        rows = await db
            .select()
            .from(logs)
            .where(eq(logs.projectId, projectId))
            .orderBy(desc(logs.timestamp))
            .limit(100);
    } else {
        rows = await db.select().from(logs);
    }

    return res.status(200).json(rows);
};

export const quickCreateLog = async (data) => {
    const { message, projectId, source, status, resource } = data;
    if (!message || !projectId || !source || !status) return false;
    const result = await db
        .insert(logs)
        .values({ message, projectId, source, status, resource })
        .returning();

    return result;
};

export const createLog = async (req, res) => {
    try {
        const { message, projectId, source, status, resource } = req.body;
        if (!message)
            return res.status(400).json({ error: "'message' is required." });
        if (!projectId)
            return res.status(400).json({ error: "'projectId' is required." });
        if (!source)
            return res.status(400).json({ error: "'source' is required." });
        if (!status)
            return res.status(400).json({ error: "'status' is required." });

        const result = await db
            .insert(logs)
            .values({ message, projectId, source, status, resource })
            .returning();

        if (result) {
            return res.status(200).json(result);
        } else {
            return res.status(500).json({ error: "An unknown error occured." });
        }
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
