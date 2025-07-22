import { db } from "../db/index.js";
import { projects } from "../db/schema/projects.js";
import { asc, eq, inArray } from "drizzle-orm";
import { quickCreateLog } from "./logs.js";
import { deployments } from "../db/schema/deployments.js";
import { infrastructure } from "../db/schema/infrastructure.js";

export const allProjects = async (req, res) => {
    const { projectId, includeInfrastructure } = req.query;
    var rows = [];

    if (projectId && typeof projectId === "string") {
        rows = await db
            .select()
            .from(projects)
            .where(eq(projects.id, projectId));
    } else {
        rows = await db.select().from(projects).orderBy(asc(projects.name));
    }

    if (includeInfrastructure === "true") {
        await Promise.all(
            rows.map(async (row) => {
                const deploymentIds = await db
                    .select()
                    .from(deployments)
                    .where(eq(deployments.projectId, row.id));
                const infrastructureRows = await db
                    .select()
                    .from(infrastructure)
                    .where(
                        inArray(
                            infrastructure.deploymentId,
                            deploymentIds.map(({ id }) => id),
                        ),
                    );

                row.infrastructure = infrastructureRows;
            }),
        );
    }

    return res.status(200).json(rows);
};

export const createProject = async (req, res) => {
    let { name, startDate, endDate } = req.body;

    startDate = new Date(startDate);
    endDate = new Date(endDate);

    if (!name) return res.status(400).json({ error: "'name' is required." });

    // Check if dates are valid..
    if (startDate.getTime() !== startDate.getTime())
        return res.status(400).json({ error: "'startDate' is invalid." });

    if (endDate.getTime() !== endDate.getTime())
        return res.status(400).json({ error: "'endDate' is invalid." });

    const result = await db
        .insert(projects)
        .values({ name, startDate, endDate })
        .returning();

    quickCreateLog({
        message: `User ${res.locals.user.id} (${res.locals.user.name}) created the project ${result[0].id} (${result[0].name}).`,
        projectId: result[0]?.id,
        source: "nucleus",
        status: "info",
        resource: result[0].id,
    });

    return res.status(200).json(result);
};

export const updateProject = async (req, res) => {
    try {
        const { projectId } = req.params;
        let { name, startDate, endDate, status } = req.body;

        startDate = new Date(startDate);
        endDate = new Date(endDate);

        // Check if dates are valid..
        if (startDate.getTime() !== startDate.getTime())
            return res.status(400).json({ error: "'startDate' is invalid." });

        if (endDate.getTime() !== endDate.getTime())
            return res.status(400).json({ error: "'endDate' is invalid." });

        const result = await db
            .update(projects)
            .set({ name, startDate, endDate, status })
            .where(eq(projects.id, projectId))
            .returning();

        quickCreateLog({
            message: `User ${res.locals.user.id} (${res.locals.user.name}) updated the project ${result[0].id} (${result[0].name}).`,
            projectId: result[0]?.id,
            source: "nucleus",
            status: "info",
            resource: result[0].id,
        });

        return res.status(200).json(result);
    } catch (e) {
        console.log(e);
    }
};

// TODO: Where to log if projects are deleted? Might link with problem of "general" application logging vs project specific.
export const deleteProject = async (req, res) => {
    try {
        const { projectId } = req.params;
        const deploymentRows = await db
            .select({ id: deployments.id })
            .from(deployments)
            .where(eq(deployments.projectId, projectId));

        if (deploymentRows.length > 0)
            return res.status(400).json({
                error: "A project cannot be removed when it contains active deployments.",
            });

        await db.delete(projects).where(eq(projects.id, projectId));

        return res.sendStatus(200);
    } catch (e) {
        console.log(e);
        return res.status(500).json({ error: "An unknown error occured." });
    }
};
