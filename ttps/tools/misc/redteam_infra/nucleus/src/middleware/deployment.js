import { db } from "../db/index.js";
import { deployments } from "../db/schema/deployments.js";

export const checkDeploymentMiddleware = async (req, res, next) => {
    const { deploymentId } = req.params;

    if (!deploymentId)
        return res.status(400).json({ error: "Deployment does not exist" });

    const deploymentRows = await db
        .select({ id: deployments.id })
        .from(deployments);

    if (
        deploymentRows.filter((deployment) => deployment.id === deploymentId)
            .length < 1
    )
        return res.status(400).json({ error: "Deployment does not exist" });

    // All else, allow access to protected route
    next();
};
