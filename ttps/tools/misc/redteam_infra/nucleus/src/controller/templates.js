import { db } from "../db/index.js";
import { templates } from "../db/schema/templates.js";
import { eq } from "drizzle-orm";

export const allTemplates = async (req, res) => {
    const rows = await db.select().from(templates);

    return res.status(200).json(rows);
};

export const createTemplate = async (req, res) => {
    try {
        const { name, type, variables, value, platform } = req.body;

        if (!name)
            return res.status(400).json({ error: "'name' is required." });
        if (!type)
            return res.status(400).json({ error: "'type' is required." });
        if (type !== "infrastructure" && type !== "configuration")
            return res.status(400).json({ error: "'type' is invalid." });

        if (type === "infrastructure") {
            if (!platform)
                return res
                    .status(400)
                    .json({ error: "'platform' is required." });
            if (platform !== "aws" && platform !== "digitalocean")
                return res
                    .status(400)
                    .json({ error: "'platform' is invalid." });
        }

        if (!value)
            return res.status(400).json({ error: "'value' is required." });
        // TODO: If value includes variables but none are set

        // TODO: IMPORTANT: Ensure that value only contains max 1 instance
        const result = await db
            .insert(templates)
            .values({ name, type, variables, value, platform })
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

export const updateTemplate = async (req, res) => {
    try {
        const { name, variables, value, platform } = req.body;

        if (!name)
            return res.status(400).json({ error: "'name' is required." });
        if (!value)
            return res.status(400).json({ error: "'value' is required." });
        // TODO: If value includes variables but none are set
        // TODO: Platform validation
        const result = await db
            .update(templates)
            .set({ name, variables, value, platform })
            .where(eq(templates.id, req.params.templateId))
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

export const deleteTemplate = async (req, res) => {
    try {
        const id = req.params.templateId;
        await db.delete(templates).where(eq(templates.id, id));
        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
