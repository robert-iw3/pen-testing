import { db } from "../db/index.js";

import { eq } from "drizzle-orm";
import { dnsRecords } from "../db/schema/dnsRecords.js";

export const allRecords = async (req, res) => {
    const { domainId } = req.params;

    const rows = await db
        .select()
        .from(dnsRecords)
        .where(eq(dnsRecords.domainId, domainId));

    return res.status(200).json(rows);
};

export const createDnsRecord = async (req, res) => {
    try {
        const { domainId } = req.params;
        const { type, name, value } = req.body;

        if (!type)
            return res.status(400).json({ error: "'type' is required." });
        if (!name)
            return res.status(400).json({ error: "'name' is required." });

        const result = await db
            .insert(dnsRecords)
            .values({ type: type.toLowerCase(), name, value, domainId })
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

export const deleteDnsRecord = async (req, res) => {
    try {
        const { dnsRecordId } = req.params;
        await db.delete(dnsRecords).where(eq(dnsRecords.id, dnsRecordId));

        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
