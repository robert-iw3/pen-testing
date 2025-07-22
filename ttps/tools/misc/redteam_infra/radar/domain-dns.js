import { promises as dns } from "dns";
import { apiFetch } from "./lib/utils";

const domainDNS = async () => {
    const domainRows = await apiFetch(`/domains`);

    // TODO: Make changeable
    dns.setServers(["8.8.8.8"]);

    const recordTypes = [
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "PTR",
        "SOA",
        "SRV",
        "TXT",
    ];

    if (domainRows.length > 0) {
        await Promise.all(
            domainRows.map(async (domain) => {
                if (
                    domain.state !== "archived" &&
                    domain.dnsAutoScan === true
                ) {
                    let newRecords = [];

                    for (const recordType of recordTypes) {
                        try {
                            const records = await dns.resolve(
                                domain.domain,
                                recordType,
                            );
                            if (records !== undefined) {
                                switch (recordType) {
                                    case "A":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: record,
                                            });
                                        });
                                        break;
                                    case "AAAA":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: record,
                                            });
                                        });
                                        break;

                                    case "CNAME":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: record,
                                            });
                                        });
                                        break;

                                    case "MX":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: JSON.stringify(record),
                                            });
                                        });
                                        break;

                                    case "NS":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: record,
                                            });
                                        });
                                        break;

                                    case "PTR":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: record,
                                            });
                                        });
                                        break;
                                    case "SOA":
                                        if (records instanceof Array) {
                                            records.forEach((record) => {
                                                newRecords.push({
                                                    type: recordType.toLowerCase(),
                                                    name: domain.domain,
                                                    value: JSON.stringify(
                                                        record,
                                                    ),
                                                });
                                            });
                                        } else {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: JSON.stringify(records),
                                            });
                                        }
                                        break;
                                    case "SRV":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: JSON.stringify(record),
                                            });
                                        });
                                        break;
                                    case "TXT":
                                        records.forEach((record) => {
                                            newRecords.push({
                                                type: recordType.toLowerCase(),
                                                name: domain.domain,
                                                value: record.join(", "),
                                            });
                                        });
                                        break;
                                }
                            }
                        } catch {
                            // Empty catch to move onto next domain
                        }
                    }

                    if (newRecords.length > 0) {
                        // For now just delete all records and replace with new ones
                        // TODO: Only delete these if found by auto scan?
                        const originalRecords = await apiFetch(
                            `/domains/${domain.id}/dns`,
                        );

                        await Promise.all(
                            originalRecords.map(async (dnsRecord) => {
                                await apiFetch(
                                    `/domains/${domain.id}/dns/${dnsRecord.id}`,
                                    "DELETE",
                                );
                            }),
                        );

                        await Promise.all(
                            newRecords.map(async (dnsRecord) => {
                                await apiFetch(
                                    `/domains/${domain.id}/dns`,
                                    "POST",
                                    dnsRecord,
                                );
                            }),
                        );

                        // TODO: What to do here? Ends up creating a LOT of logs
                        // await apiFetch(`/logs`, "POST", {
                        //     message: `DNS records automatically updated for domain ${domain.id} (${domain.domain}).`,
                        //     projectId: domain.projectId,
                        //     source: "radar",
                        //     status: "info",
                        //     resource: domain.id,
                        // });
                    }
                }
            }),
        );
    }

    return process.exit();
};

domainDNS();
