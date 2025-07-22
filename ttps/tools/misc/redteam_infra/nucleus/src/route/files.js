import express from "express";
import {
  allFiles,
  createFile,
  deleteFile,
  updateFile,
} from "../controller/files.js";

const router = express.Router();

router.get("/", allFiles);
router.post("/", createFile);
router.put("/:fileId", updateFile);
router.delete("/:fileId", deleteFile);

export { router };
