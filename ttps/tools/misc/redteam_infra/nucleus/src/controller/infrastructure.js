import { db } from "../db/index.js";
import { infrastructure } from "../db/schema/infrastructure.js";
import { tailscaleUserData } from "../templates/system/general/tailscale_user_data.sh.js";
import { eq } from "drizzle-orm";
import { templates } from "../db/schema/templates.js";
import fs from "fs";
import path from "path";
import { resources } from "../db/schema/resources.js";
import { deployments } from "../db/schema/deployments.js";
import { integrations } from "../db/schema/integrations.js";
import { settings } from "../db/schema/settings.js";

const updateTerraformResourceNames = (terraform, id) => {
    return terraform.replace(
        /resource\s+"([^"]+)"\s+"([^"]+)"/g,
        (_, resourceType, resourceName) => {
            const newResourceName = `${resourceName}_${id}`;
            return `resource "${resourceType}" "${newResourceName}"`;
        },
    );
};

const injectSshKey = (resourceType, resource, region = "") => {
    const lines = resource.split("\n");

    if (resourceType === "aws_instance") {
        lines.splice(
            lines.length - 1,
            0,
            "\n  key_name = aws_key_pair.key_pair.key_name\n",
        );
    } else if (resourceType === "digitalocean_droplet") {
        lines.splice(
            lines.length - 1,
            0,
            "\n  ssh_keys = [digitalocean_ssh_key.key_pair.id]\n",
            `\n  region = "${region}"\n`,
        );
    }
    return lines.join("\n");
};

const injectUserDataScript = (resource, userDataScript) => {
    const userDataField = `  user_data = <<-EOF${userDataScript}\n\tEOF\n`;
    const lines = resource.split("\n");
    lines.splice(lines.length - 1, 0, userDataField);
    return lines.join("\n");
};

const injectTerraformVariables = (resource, variables) => {
    return variables.reduce((acc, variable) => {
        return acc.replaceAll(`$$${variable.name}$$`, variable.value);
    }, resource);
};

const parseTerraformResource = (terraform) => {
    const regex = /resource\s+"([^"]+)"\s+"([^"]+)"/;
    const match = terraform.match(regex);
    return match ? { type: match[1], name: match[2] } : null;
};

const extractTerraformResources = (terraform) => {
    const resourceRegex =
        /resource\s+"[\w-]+"\s+"[\w-]+"\s+\{(?:[^{}]*|\{[^{}]*\})*\}/g;
    return terraform.match(resourceRegex) || [];
};

export const allInfrastructure = async (req, res) => {
    const { deploymentId } = req.params;

    if (!deploymentId) {
        return res
            .status(400)
            .json({ error: "error 'deploymentId' is required" });
    }

    const rows = await db
        .select()
        .from(infrastructure)
        .where(eq(infrastructure.deploymentId, deploymentId));

    return res.status(200).json(rows);
};

export const updateInfrastructure = async (req, res) => {
    const { infrastructureId } = req.params;
    const { name, description, configurations } = req.body;

    if (name && name === "") {
        return res.status(400).json({ error: "'name' cannot be blank." });
    }

    configurations.forEach((config) => {
        config.variables.forEach((variable) => {
            if (variable.type === "infrastructure-id") {
                variable.value = infrastructureId;
            }

            if (variable.type === "file" && Array.isArray(variable.variables)) {
                variable.variables.forEach((nestedVar) => {
                    if (nestedVar.type === "infrastructure-id") {
                        nestedVar.value = infrastructureId;
                    }
                });
            }
        });
    });

    const updatedRow = await db
        .update(infrastructure)
        .set({ name, description, configurations })
        .where(eq(infrastructure.id, infrastructureId))
        .returning();

    return res.status(200).json(updatedRow);
};

export const createInfrastructure = async (req, res) => {
    try {
        const { deploymentId } = req.params;

        if (!deploymentId) {
            return res
                .status(400)
                .json({ error: "error 'deploymentId' is required" });
        }

        // TODO: Check these
        const { name, infrastructureTemplateId, description, variables } =
            req.body;

        if (!name) {
            return res.status(400).json({ error: "error 'name' is required" });
        }

        if (!infrastructureTemplateId) {
            return res.status(400).json({
                error: "error 'infrastructureTemplateId' is required",
            });
        }

        if (
            variables.length &&
            !variables.every((variable) => {
                if (variable.type !== "infrastructure-id")
                    return (
                        variable.name && variable.value && variable.value !== ""
                    );
                return true;
            })
        ) {
            return res
                .status(400)
                .json({ error: "error 'variables' is invalid" });
        }

        const deploymentDir = path.join("/app/deployments", deploymentId);
        const terraformDir = path.join(deploymentDir, "terraform");

        const [deployment] = await db
            .select({
                tailscaleId: deployments.tailscaleId,
                region: deployments.region,
            })
            .from(deployments)
            .where(eq(deployments.id, deploymentId));

        const [tailscaleKey] = await db
            .select()
            .from(integrations)
            .where(eq(integrations.id, deployment.tailscaleId));

        const [template] = await db
            .select()
            .from(templates)
            .where(eq(templates.id, infrastructureTemplateId));

        const [newInfrastructure] = await db
            .insert(infrastructure)
            .values({
                deploymentId,
                name,
                infrastructureTemplateId,
                description,
            })
            .returning();

        const settingsData = await db.select().from(settings);
        const tagSetting = settingsData.find(
            (setting) => setting.name === "tailscaleTag",
        );
        const userDataSetting = settingsData.find(
            (setting) => setting.name === "userData",
        );

        const updatedVariables = variables.map((v) => {
            if (v.type === "infrastructure-id") {
                return { ...v, value: newInfrastructure.id };
            }
            return v;
        });

        const resourceArray = extractTerraformResources(template.value);
        let finalContent = "";
        const updatedResourceMappings = [];

        await Promise.all(
            resourceArray.map(async (resource) => {
                const resourceUUID = crypto.randomUUID();
                const oldParsedResource = parseTerraformResource(resource);

                let updatedResource = injectTerraformVariables(
                    resource,
                    updatedVariables,
                );
                updatedResource = updateTerraformResourceNames(
                    updatedResource,
                    resourceUUID,
                );

                if (
                    oldParsedResource.type === "aws_instance" ||
                    oldParsedResource.type === "digitalocean_droplet"
                ) {
                    updatedResource = injectSshKey(
                        oldParsedResource.type,
                        updatedResource,
                        deployment.region,
                    );

                    const tailscaleResult = await fetch(
                        "https://api.tailscale.com/api/v2/tailnet/-/keys?all=true",
                        {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json",
                                Authorization: `Bearer ${tailscaleKey.secretKey}`,
                            },
                            body: JSON.stringify({
                                capabilities: {
                                    devices: {
                                        create: {
                                            reusable: false,
                                            ephemeral: true,
                                            preauthorized: true,
                                            tags: tagSetting?.value
                                                ? [`tag:${tagSetting.value}`]
                                                : [],
                                        },
                                    },
                                },
                                expirySeconds: 86400,
                            }),
                        },
                    );

                    const newKey = await tailscaleResult.json();

                    const userDataScript = tailscaleUserData({
                        authKey: newKey.key,
                        resourceId: newInfrastructure.id,
                        resourceName: name,
                        custom: userDataSetting?.value
                            ? userDataSetting.value
                            : "",
                    });

                    updatedResource = injectUserDataScript(
                        updatedResource,
                        userDataScript,
                    );
                }

                finalContent = finalContent.concat(updatedResource + "\n\n");

                const newParsedResource =
                    parseTerraformResource(updatedResource);
                updatedResourceMappings.push({
                    old: `${oldParsedResource?.type}.${oldParsedResource?.name}`,
                    new: `${newParsedResource?.type}.${newParsedResource?.name}`,
                });

                await db.insert(resources).values({
                    id: resourceUUID,
                    infrastructureId: newInfrastructure.id,
                    infrastructureTemplateId,
                    resourceType: newParsedResource.type,
                    resourceName: newParsedResource.name,
                    status: "pending",
                });
            }),
        );

        updatedResourceMappings.forEach((mapping) => {
            finalContent = finalContent.replace(mapping.old, mapping.new);
        });

        fs.writeFileSync(
            path.join(terraformDir, `${newInfrastructure.id}.tf`),
            finalContent,
        );

        return res.status(200).json(newInfrastructure);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};

export const deleteInfrastructure = async (req, res) => {
    const { deploymentId, infrastructureId } = req.params;

    const deploymentDir = path.join("/app/deployments", deploymentId);
    const terraformDir = path.join(deploymentDir, "terraform");

    if (fs.existsSync(path.join(terraformDir, `${infrastructureId}.tf`))) {
        fs.rmSync(path.join(terraformDir, `${infrastructureId}.tf`));
    }

    await db
        .delete(infrastructure)
        .where(eq(infrastructure.id, infrastructureId));

    return res
        .status(200)
        .json({ message: "Infrastructure deleted successfully" });
};
