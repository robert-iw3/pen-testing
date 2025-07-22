import { db } from "../db/index.js";
import { domains } from "../db/schema/domains.js";
import { eq } from "drizzle-orm";

export const allDomains = async (req, res) => {
    const { projectId } = req.query;

    var rows = [];

    if (projectId) {
        rows = await db
            .select()
            .from(domains)
            .where(eq(domains.projectId, projectId));
    } else {
        rows = await db.select().from(domains);
    }

    return res.status(200).json(rows);
};

export const createDomain = async (req, res) => {
    try {
        const { domain, projectId } = req.body;
        if (!domain)
            return res.status(400).json({ error: "'domain' is required." });
        if (!projectId)
            return res.status(400).json({ error: "'projectId' is required." });

        const result = await db
            .insert(domains)
            .values({ domain, projectId })
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

export const deleteDomain = async (req, res) => {
    try {
        const { domainId } = req.params;
        await db.delete(domains).where(eq(domains.id, domainId));

        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};

export const updateDomain = async (req, res) => {
    try {
        const { domainId } = req.params;
        const original = await db
            .select()
            .from(domains)
            .where(eq(domains.id, domainId));

        var {
            domain,
            category,
            state,
            stateAutoScan,
            dnsAutoScan,
            description,
            archived,
        } = req.body;

        // Check if at least one of the variables has a value
        const hasValue = [
            domain,
            category,
            state,
            stateAutoScan,
            dnsAutoScan,
            description,
            archived,
        ].some(
            (value) => value !== undefined && value !== null && value !== "",
        );

        if (!hasValue)
            return res
                .status(400)
                .json({ error: "A value to update is required." });

        const updated = new Date();

        // TODO: Commenting as this breaks Radar
        // if (state && original[0].stateAutoScan)
        //     return res.status(400).json({
        //         error: "'state' cannot be updated when 'stateAutoScan' is true.",
        //     });

        if (archived && archived !== "false") state = "archived";
        if (
            typeof archived !== "undefined" &&
            (archived === false || archived === "false")
        )
            state = "pending-analysis";

        const stateUpdated = state !== undefined ? new Date() : undefined;

        const updatedDomain = await db
            .update(domains)
            .set({
                domain,
                category,
                state,
                stateUpdated,
                stateAutoScan,
                dnsAutoScan,
                description,
                updated,
            })
            .where(eq(domains.id, domainId))
            .returning();

        return res.status(200).json(updatedDomain);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
