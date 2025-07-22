import express from "express";
import {
    allDomains,
    createDomain,
    deleteDomain,
    updateDomain,
} from "../controller/domains.js";

const router = express.Router({ mergeParams: true });

router.get("/", allDomains);
router.post("/", createDomain);
router.put("/:domainId", updateDomain);
router.delete("/:domainId", deleteDomain);

export { router };
