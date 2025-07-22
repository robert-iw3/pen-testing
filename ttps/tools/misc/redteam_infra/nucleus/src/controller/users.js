import { db } from "../db/index.js";
import { users, userSafeSelect } from "../db/schema/users.js";
import { hash } from "../lib/crypto.js";
import { eq } from "drizzle-orm";

export const allUsers = async (req, res) => {
    const rows = await db.select(userSafeSelect).from(users);

    return res.status(200).json(rows);
};

export const addUser = async (req, res) => {
    try {
        const { name, email, role, password, confirmPassword } = req.body;
        const roles = ["admin", "operator", "readonly"];

        if (!name)
            return res.status(400).json({ error: "'name' is required." });
        if (!email)
            return res.status(400).json({ error: "'email' is required." });
        if (!role)
            return res.status(400).json({ error: "'role' is required." });
        if (!roles.includes(role))
            return res.status(400).json({ error: "'role' is invalid." });
        if (!password)
            return res.status(400).json({ error: "'password' is required." });
        if (!confirmPassword)
            return res
                .status(400)
                .json({ error: "'confirmPassword' is required." });

        if (password !== confirmPassword)
            return res.status(400).json({
                error: "'password' and 'confirmPassword' do not match.",
            });

        if (!/^[\w-+#\.]+@([\w-]+\.)+[\w-]{2,5}$/.test(email))
            return res.status(400).json({ error: "'email' is invalid." });

        // TODO: Check role is valid

        var newUser = await db
            .insert(users)
            .values({ name, email, role, password: await hash(password) })
            .returning();

        delete newUser[0].password;

        return res.status(200).json(newUser[0]);
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};

export const deleteUser = async (req, res) => {
    try {
        const id = req.params.userId;

        const currentUsers = await db.select(userSafeSelect).from(users);
        if (currentUsers.length === 1) {
            return res
                .status(400)
                .json({ error: "Cannot delete the last user." });
        }

        const userToDelete = await db
            .select(userSafeSelect)
            .from(users)
            .where(eq(users.id, id));
        if (userToDelete[0]?.role === "admin") {
            const admins = currentUsers.filter((user) => user.role === "admin");
            if (admins.length === 1) {
                return res
                    .status(400)
                    .json({ error: "Cannot delete the last admin user." });
            }
        }

        if (userToDelete[0]?.role === "service")
            return res
                .status(400)
                .json({ error: "Cannot delete service accounts." });

        await db.delete(users).where(eq(users.id, id));

        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
