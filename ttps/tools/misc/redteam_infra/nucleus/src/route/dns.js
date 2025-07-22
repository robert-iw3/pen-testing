import express from "express";
import {
    allRecords,
    createDnsRecord,
    deleteDnsRecord,
} from "../controller/dns.js";

const router = express.Router({ mergeParams: true });

router.get("/", allRecords);
router.post("/", createDnsRecord);
router.delete("/:dnsRecordId", deleteDnsRecord);

export { router };
