import { apiFetch } from "./lib/utils";

const getDomains = async () => {
    const rows = await apiFetch(`/domains`);

    if (rows.length > 0) {
        // Custom sort the date with null first, then descending stateUpdated. Only grab the first two due to VT API limits
        const data = rows
            .sort((a, b) => {
                if (a.stateUpdated === null) return -1; // `a` goes first if `stateUpdated` is null
                if (b.stateUpdated === null) return 1; // `b` goes first if `stateUpdated` is null
                return new Date(a.stateUpdated) - new Date(b.stateUpdated); // Sort by date (oldest first)
            })
            .slice(0, 2);

        await Promise.all(
            data.map(async (domain) => {
                if (
                    domain.state !== "burnt" &&
                    domain.state !== "archived" &&
                    domain.stateAutoScan === true
                ) {
                    // Decide what the new state will be if other checks succeed
                    let state =
                        domain.state === "aging"
                            ? "aging"
                            : domain.state === "unhealthy"
                              ? "unhealthy"
                              : "healthy";
                    let description = "";
                    let category = domain?.category
                        ? domain.category
                        : "unknown";

                    try {
                        // Fetch domain data from virus total
                        const raw = await fetch(
                            `https://www.virustotal.com/api/v3/domains/${domain.domain}`,
                            {
                                headers: {
                                    "x-apikey": process.env.VT_API_KEY,
                                    "Content-Type": "application/json",
                                    accept: "application/json",
                                },
                            },
                        );

                        const result = await raw.json();

                        // CHECK 1: If the domain has been analysed in the last 24h
                        if (result.data.attributes?.last_analysis_date) {
                            const lastAnalysis =
                                result.data.attributes.last_analysis_date *
                                1000;
                            const now = Date.now();
                            const oneDayAgo = now - 24 * 60 * 60 * 1000; // Time 24 hours ago in milliseconds

                            if (
                                lastAnalysis >= oneDayAgo &&
                                lastAnalysis <= now
                            ) {
                                state = "burnt";
                                description =
                                    "This domain has been manually analysed by VirusTotal in the past 24 hours.";
                            }
                        }

                        // CHECK 2: If the domain has a suspicious or malicious reputation
                        if (result.data.attributes?.last_analysis_stats) {
                            const { malicious, suspicious } =
                                result.data.attributes?.last_analysis_stats;
                            if (suspicious > 0) {
                                state = "burnt";
                                description =
                                    "This domain has a suspicious reputation from at least one vendor.";
                            }

                            if (malicious > 0) {
                                state = "burnt";
                                description =
                                    "This domain has a malicious reputation from at least one vendor.";
                            }
                        }

                        // Get and set the domain category
                        if (
                            Object.values(result.data.attributes.categories)
                                .length > 0
                        ) {
                            category = Object.values(
                                result.data.attributes.categories,
                            )[0];
                        }
                    } catch (e) {
                        console.log(e);
                    } finally {
                        const newData = await apiFetch(
                            `/domains/${domain.id}`,
                            "PUT",
                            {
                                state,
                                description,
                                category,
                                stateUpdated: new Date(),
                                updated: new Date(),
                            },
                        );

                        // TODO: What to do here? Ends up creating a LOT of logs
                        // await apiFetch(`/logs`, "POST", {
                        //     message: `Domain health automatically checked for domain ${domain.id} (${domain.domain}).`,
                        //     projectId: domain.projectId,
                        //     source: "radar",
                        //     status: "info",
                        //     resource: domain.id,
                        // });
                    }
                }
            }),
        );

        return process.exit();
    }
};

getDomains();
