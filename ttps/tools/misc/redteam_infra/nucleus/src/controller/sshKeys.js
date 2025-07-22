import { db } from "../db/index.js";
import { sshKeys } from "../db/schema/sshKeys.js";
import { generateKeyPairSync } from "crypto";
import { eq } from "drizzle-orm";

export const allSshKeys = async (req, res) => {
    const rows = await db
        .select({
            id: sshKeys.id,
            name: sshKeys.name,
            publicKey: sshKeys.public,
        })
        .from(sshKeys);

    return res.status(200).json(rows);
};

export const createSshKey = async (req, res) => {
    try {
        const { name } = req.body;
        if (!name)
            return res.status(400).json({ error: "'name' is required." });

        const { publicKey, privateKey } = generateKeyPairSync("rsa", {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: "pkcs1",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs1",
                format: "pem",
            },
        });

        const result = await db
            .insert(sshKeys)
            .values({ name, public: publicKey, private: privateKey })
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

export const deleteSshKey = async (req, res) => {
    try {
        const id = req.params.sshKeyId;
        await db.delete(sshKeys).where(eq(sshKeys.id, id));

        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
