import express from "express";
import {
    allProjects,
    createProject,
    updateProject,
    deleteProject,
} from "../controller/projects.js";
import { checkProjectMiddleware } from "../middleware/project.js";

const router = express.Router();

router.get("/", allProjects);
router.post("/", createProject);
router.put("/:projectId", checkProjectMiddleware, updateProject);
router.delete("/:projectId", checkProjectMiddleware, deleteProject);

export { router };
