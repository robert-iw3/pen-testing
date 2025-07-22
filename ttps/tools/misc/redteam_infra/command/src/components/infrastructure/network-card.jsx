"use client";

import { cn } from "@/lib/utils";
import {
    Card,
    CardHeader,
    CardTitle,
    CardContent,
    CardDescription,
} from "../ui/card";
import { Label } from "../ui/label";

export function NetworkCard({ className, infrastructure }) {
    var privateIps = infrastructure.resources.map((r) => r.privateIp);
    var publicIps = infrastructure.resources.map((r) => r.publicIp);
    var tailscaleIps = infrastructure.resources.map((r) => r.tailscaleIp);

    // Remove duplicates and filter out empty strings
    privateIps = [...new Set(privateIps)].filter((n) => n);
    publicIps = [...new Set(publicIps)].filter((n) => n);
    tailscaleIps = [...new Set(tailscaleIps)].filter((n) => n);

    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Networking</CardTitle>
                    <CardDescription className="text-xs text-muted-foreground mt-1.5">
                        Networking information for this infrastructure.
                    </CardDescription>
                </div>
                <div
                    className="flex items-center"
                    style={{ marginTop: 0 }}
                ></div>
            </CardHeader>
            <CardContent>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        {publicIps.length > 1 ? (
                            <>
                                <Label>Public IPs</Label>
                                <p className="text-sm">
                                    {publicIps.join(", ")}
                                </p>
                            </>
                        ) : (
                            <>
                                <Label>Public IP</Label>
                                <p className="text-sm">
                                    {publicIps[0] || "N/A"}
                                </p>
                            </>
                        )}
                    </div>
                    <div className="grid gap-2">
                        {privateIps.length > 1 ? (
                            <>
                                <Label>Private IPs</Label>
                                <p className="text-sm">
                                    {privateIps.join(", ")}
                                </p>
                            </>
                        ) : (
                            <>
                                <Label>Private IP</Label>
                                <p className="text-sm">
                                    {privateIps[0] || "N/A"}
                                </p>
                            </>
                        )}
                    </div>
                    <div className="grid gap-2">
                        {tailscaleIps.length > 1 ? (
                            <>
                                <Label>Tailscale IPs</Label>
                                <p className="text-sm">
                                    {tailscaleIps.join(", ")}
                                </p>
                            </>
                        ) : (
                            <>
                                <Label>Tailscale IP</Label>
                                <p className="text-sm">
                                    {tailscaleIps[0] || "N/A"}
                                </p>
                            </>
                        )}
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
