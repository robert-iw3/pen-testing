import express from "express";
import {
    allInfrastructure,
    createInfrastructure,
    deleteInfrastructure,
    updateInfrastructure,
} from "../controller/infrastructure.js";

const router = express.Router({ mergeParams: true });

router.get("/", allInfrastructure);
router.post("/", createInfrastructure);
router.put("/:infrastructureId", updateInfrastructure);
router.delete("/:infrastructureId", deleteInfrastructure);

export { router };
