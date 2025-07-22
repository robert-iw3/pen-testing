import express from "express";
import { allLogs, createLog } from "../controller/logs.js";

const router = express.Router({ mergeParams: true });

router.get("/", allLogs);
router.post("/", createLog);

export { router };
