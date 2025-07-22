import express from "express";
import {
    allIntegrations,
    createIntegration,
    deleteIntegration,
} from "../controller/integrations.js";

const router = express.Router();

router.get("/", allIntegrations);
router.post("/", createIntegration);
router.delete("/:collectionId", deleteIntegration);

export { router };
