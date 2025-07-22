import { db } from "../db/index.js";
import { settings } from "../db/schema/settings.js";
import { eq } from "drizzle-orm";

export const allSettings = async (req, res) => {
    const rows = await db.select().from(settings);

    return res.status(200).json(rows);
};

export const updateSetting = async (req, res) => {
    try {
        const { name, value } = req.body;

        if (!name)
            return res.status(400).json({ error: "'name' is required." });

        const [setting] = await db
            .select()
            .from(settings)
            .where(eq(settings.name, name));
        let result = [];

        if (!setting) {
            result = await db
                .insert(settings)
                .values({ name, value: value || "" })
                .returning();
        } else {
            result = await db
                .update(settings)
                .set({ value: value || "" })
                .where(eq(settings.name, name))
                .returning();
        }

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
