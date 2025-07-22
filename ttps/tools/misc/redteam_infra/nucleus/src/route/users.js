import express from "express";
import { addUser, allUsers, deleteUser } from "../controller/users.js";

const router = express.Router();

router.get("/", allUsers);
router.post("/", addUser);
router.delete("/:userId", deleteUser);

export { router };
