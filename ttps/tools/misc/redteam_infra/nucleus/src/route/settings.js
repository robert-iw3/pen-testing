import express from "express";
import { allSettings, updateSetting } from "../controller/settings.js";

const router = express.Router();

router.get("/", allSettings);
router.post("/", updateSetting);

export { router };
