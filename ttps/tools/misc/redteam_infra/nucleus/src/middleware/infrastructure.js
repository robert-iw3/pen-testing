import { db } from "../db/index.js";
import { infrastructure } from "../db/schema/infrastructure.js";

export const checkInfrastructureMiddleware = async (req, res, next) => {
    const { infrastructureId } = req.params;

    if (!infrastructureId)
        return res.status(400).json({ error: "Infrastructure does not exist" });

    const infrastructureRows = await db
        .select({ id: infrastructure.id })
        .from(infrastructure);

    if (
        infrastructureRows.filter((row) => row.id === infrastructureId).length <
        1
    )
        return res.status(400).json({ error: "Infrastructure does not exist" });

    // All else, allow access to protected route
    next();
};
