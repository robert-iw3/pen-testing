import { db } from "../db/index.js";
import { resources } from "../db/schema/resources.js";
import { eq } from "drizzle-orm";
import { deployments } from "../db/schema/deployments.js";
import { integrations } from "../db/schema/integrations.js";
import { infrastructure } from "../db/schema/infrastructure.js";

export const allResources = async (req, res) => {
    const { infrastructureId, deploymentId } = req.params;

    var rows = await db
        .select()
        .from(resources)
        .where(eq(resources.infrastructureId, infrastructureId));

    if (
        rows.find(
            (row) =>
                (row.resourceType === "aws_instance" ||
                    row.resourceType === "digitalocean_droplet") &&
                row.tailscaleIp === null,
        )
    ) {
        const [deployment] = await db
            .select({ tailscaleId: deployments.tailscaleId })
            .from(deployments)
            .where(eq(deployments.id, deploymentId));

        const [tailscaleKey] = await db
            .select()
            .from(integrations)
            .where(eq(integrations.id, deployment.tailscaleId));

        const [infrastructureRows] = await db
            .select({ name: infrastructure.name })
            .from(infrastructure)
            .where(eq(infrastructure.id, infrastructureId));

        const tailscaleRes = await fetch(
            "https://api.tailscale.com/api/v2/tailnet/-/devices",
            {
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${tailscaleKey.secretKey}`,
                },
            },
        );

        const tailscaleJSON = await tailscaleRes.json();
        const tailscaleHosts = tailscaleJSON.devices;

        rows = rows.map(async (row) => {
            const tailscaleIp = tailscaleHosts.find((host) => {
                return (
                    host.hostname ===
                    String(
                        infrastructureRows.name +
                            "-" +
                            infrastructureId.split("-")[0],
                    )
                        .toLowerCase() // Lowercase everything
                        .replace(/[^a-z0-9-]+/g, "-") // Replace invalid characters with hyphen
                        .replace(/^-+|-+$/g, "") // Trim leading/trailing hyphens
                        .replace(/-+/g, "-") // Collapse multiple hyphens
                        .slice(0, 63)
                ); // Trim to 63 characters max
            })?.addresses[0];

            if (tailscaleIp) {
                await db
                    .update(resources)
                    .set({ tailscaleIp })
                    .where(eq(resources.id, row.id));
            }
            row.tailscaleIp = tailscaleIp;
            return { ...row, tailscaleIp };
        });
    }
    return res.status(200).json(await Promise.all(rows));
};
