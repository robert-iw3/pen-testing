import { db } from "../db/index.js";
import { projects } from "../db/schema/projects.js";

export const checkProject = async (projectId) => {
    const projectRows = await db.select({ id: projects.id }).from(projects);

    if (projectRows.filter((project) => project.id === projectId).length < 1)
        return false;

    return true;
};

export const checkProjectMiddleware = async (req, res, next) => {
    const { projectId } = req.params;

    if (!(await checkProject(projectId)))
        return res.status(400).json({ error: "Project does not exist" });

    // All else, allow access to protected route
    next();
};
