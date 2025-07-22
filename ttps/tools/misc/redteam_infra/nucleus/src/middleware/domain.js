import { db } from "../db/index.js";
import { domains } from "../db/schema/domains.js";

export const checkDomainMiddleware = async (req, res, next) => {
    const { domainId } = req.params;

    if (!domainId)
        return res.status(400).json({ error: "Domain does not exist" });

    const domainRows = await db.select({ id: domains.id }).from(domains);

    if (domainRows.filter((domain) => domain.id === domainId).length < 1)
        return res.status(400).json({ error: "Domain does not exist" });

    // All else, allow access to protected route
    next();
};
