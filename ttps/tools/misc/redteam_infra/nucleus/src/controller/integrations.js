import { db } from "../db/index.js";
import {
    integrations,
    integrationPlatformEnum,
} from "../db/schema/integrations.js";
import { eq } from "drizzle-orm";

export const allIntegrations = async (req, res) => {
    const rows = await db
        .select({
            id: integrations.id,
            name: integrations.name,
            platform: integrations.platform,
        })
        .from(integrations);

    return res.status(200).json(rows);
};

export const createIntegration = async (req, res) => {
    try {
        const { name, platform, keyId, secretKey } = req.body;

        if (!name)
            return res.status(400).json({ error: "'name' is required." });
        if (!platform)
            return res.status(400).json({ error: "'platform' is required." });
        if (!integrationPlatformEnum.enumValues.includes(platform))
            return res.status(400).json({ error: "Platform not supported." });
        if (platform === "aws" && !keyId)
            return res.status(400).json({ error: "'keyId' is required." });
        if (!secretKey)
            return res.status(400).json({ error: "'secretKey' is required." });

        const result = await db
            .insert(integrations)
            .values({ name, platform, keyId, secretKey })
            .returning();

        if (result) {
            return res.status(200).json({
                id: result[0].id,
                platform: result[0].platform,
                name: result[0].name,
            });
        } else {
            return res.status(500).json({ error: "An unknown error occured." });
        }
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};

export const deleteIntegration = async (req, res) => {
    try {
        const id = req.params.integrationId;
        await db.delete(integrations).where(eq(integrations.id, id));

        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
