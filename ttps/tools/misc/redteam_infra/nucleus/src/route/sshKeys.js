import express from "express";
import {
    allSshKeys,
    createSshKey,
    deleteSshKey,
} from "../controller/sshKeys.js";

const router = express.Router();

router.get("/", allSshKeys);
router.post("/", createSshKey);
router.delete("/:sshKeyId", deleteSshKey);

export { router };
