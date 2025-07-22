import { db } from "../db/index.js";
import { files } from "../db/schema/files.js";
import { eq } from "drizzle-orm";

export const allFiles = async (req, res) => {
    const rows = await db.select().from(files);

    return res.status(200).json(rows);
};

export const createFile = async (req, res) => {
    try {
        const { name, extension, variables, value } = req.body;

        if (!name)
            return res.status(400).json({ error: "'name' is required." });
        if (!extension)
            return res.status(400).json({ error: "'extension' is required." });
        if (!value)
            return res.status(400).json({ error: "'value' is required." });
        // TODO: If value includes variables but none are set

        const result = await db
            .insert(files)
            .values({ name, extension, variables, value })
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

export const updateFile = async (req, res) => {
    try {
        const { name, extension, variables, value } = req.body;
        const id = req.params.fileId;

        if (!name)
            return res.status(400).json({ error: "'name' is required." });
        if (!extension)
            return res.status(400).json({ error: "'extension' is required." });
        if (!value)
            return res.status(400).json({ error: "'value' is required." });
        // TODO: If value includes variables but none are set

        const result = await db
            .update(files)
            .set({ name, extension, variables, value })
            .where(eq(files.id, id))
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

export const deleteFile = async (req, res) => {
    try {
        const id = req.params.fileId;
        await db.delete(files).where(eq(files.id, id));
        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
