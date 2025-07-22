import { eq } from "drizzle-orm/mysql-core/expressions";
import jwt from "jsonwebtoken";
import { db } from "../db/index.js";
import { users } from "../db/schema/users.js";
import { verify } from "../lib/crypto.js";

export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res
            .status(400)
            .json({ error: "'email' and 'password' is required." });

    const rows = await db.select().from(users).where(eq(users.email, email));

    if (rows.length < 1) {
        // Verify against fake hash to equalise the response times.
        await verify(
            "$argon2i$v=19$m=16,t=2,p=1$" +
                [...Array(12)]
                    .map(() => Math.floor(Math.random() * 16).toString(16))
                    .join("") +
                "$EoBP1ElZQJ8ESyQ4KQ/avQ",
            "anything",
        );
        return res
            .status(401)
            .json({ error: "Invalid email address or password." });
    }

    if (!(await verify(rows[0].password, password)))
        return res
            .status(401)
            .json({ error: "Invalid email address or password." });

    const accessToken = jwt.sign(
        { id: rows[0].id },
        process.env.NUCLEUS_SECRET,
    );

    return res.status(200).json({
        id: rows[0].id,
        email: rows[0].email,
        name: rows[0].name,
        role: rows[0].role,
        accessToken,
    });
};
