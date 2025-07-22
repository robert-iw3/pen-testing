import crypto from "crypto";

import { db } from "../db/index.js";
import { users } from "../db/schema/users.js";
import { templates } from "../db/schema/templates.js";
import { files } from "../db/schema/files.js";
import { hash } from "./crypto.js";
import { readdir } from "fs/promises";
import path from "path";
import fs from "fs/promises";

async function findJSONFiles(dir) {
    let results = [];
    const entries = await readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            const nestedFiles = await findJSONFiles(fullPath);
            results = results.concat(nestedFiles);
        } else if (entry.isFile() && fullPath.endsWith(".json")) {
            results.push(fullPath);
        }
    }

    return results;
}

async function loadTemplatesFromDirectory(rootDir) {
    const jsonFiles = await findJSONFiles(rootDir);
    const templates = [];

    for (const file of jsonFiles) {
        const fileContent = await fs.readFile(file, "utf8");
        try {
            const template = JSON.parse(fileContent);
            templates.push(template);
        } catch (err) {
            console.warn(`Invalid JSON in ${file}: ${err.message}`);
        }
    }

    return templates;
}

const main = async () => {
    const existingUsers = await db.select().from(users);
    if (existingUsers.length < 1) {
        // Assume unseeded

        // Generate new password
        const password = crypto.randomBytes(16).toString("hex");

        console.log(`
###################################
# Forge Admin Credentials
# User: admin@lodestar-forge.local
# Password: ${password}
###################################
`);
        await db.insert(users).values([
            {
                name: "Forge Admin",
                email: "admin@lodestar-forge.local",
                password: await hash(password),
                role: "admin",
            },
            {
                id: "1e768b85-061c-42db-b466-d875001135eb",
                name: "radar-service",
                email: "radar@lodestar-forge.local",
                password: await hash(crypto.randomBytes(64).toString("hex")),
                role: "service",
            },
        ]);

        const loadedTemplates = await loadTemplatesFromDirectory(
            "/app/src/templates/default",
        );

        for (const template of loadedTemplates) {
            const { name, type, variables, value, extension, platform } =
                template;
            if (type === "infrastructure" || type === "configuration") {
                await db.insert(templates).values({
                    name,
                    type,
                    variables,
                    value,
                    platform,
                });
            } else if (type === "file") {
                await db.insert(files).values({
                    name,
                    type,
                    variables,
                    value,
                    extension,
                });
            }
        }
    }
};

main().then(() => process.exit());
