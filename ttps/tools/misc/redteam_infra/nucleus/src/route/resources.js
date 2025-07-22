import express from "express";
import { allResources } from "../controller/resources.js";

const router = express.Router({ mergeParams: true });

router.get("/", allResources);

export { router };
