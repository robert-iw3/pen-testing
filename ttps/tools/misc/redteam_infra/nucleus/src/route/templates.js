import express from "express";
import {
    allTemplates,
    createTemplate,
    updateTemplate,
    deleteTemplate,
} from "../controller/templates.js";

const router = express.Router();

router.get("/", allTemplates);
router.post("/", createTemplate);
router.put("/:templateId", updateTemplate);
router.delete("/:templateId", deleteTemplate);

export { router };
