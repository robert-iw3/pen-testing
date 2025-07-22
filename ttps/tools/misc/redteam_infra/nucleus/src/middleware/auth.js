import jwt from "jsonwebtoken";
import { db } from "../db/index.js";
import { users } from "../db/schema/users.js";
import { eq } from "drizzle-orm/pg-core/expressions";

export const authenticatedUser = (req, res, next) => {
    // Get accessToken
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    // If token doesnt exits
    if (token == null) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, process.env.NUCLEUS_SECRET, async (err, body) => {
        // If jwt verify failed, return error
        if (err) return res.status(401).json({ error: "Unauthorized" });

        // Check user exists in DB
        const rows = await db
            .select({ id: users.id, name: users.name })
            .from(users)
            .where(eq(users.id, body.id));

        // If not, return error
        if (rows.length < 1)
            return res.status(401).json({ error: "Unauthorized" });

        // All else, allow access to protected route
        res.locals.user = {
            id: rows[0]?.id,
            name: rows[0]?.name,
        };
        next();
    });
};
