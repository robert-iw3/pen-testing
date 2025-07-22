"use client";

import { cn } from "@/lib/utils";
import {
    Card,
    CardHeader,
    CardTitle,
    CardContent,
    CardFooter,
    CardDescription,
} from "../ui/card";
import { Tag } from "../common/tag";
import { Button } from "../ui/button";
import { Undo2, Circle, CircleCheck, CircleDashed } from "lucide-react";
import { LogDialog } from "./log-dialog";
import {
    prepareDeployment,
    deployDeployment,
    configureDeployment,
} from "@/actions/deployments";
import { RefreshButton } from "./refresh-button";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "../ui/tooltip";

export function StatusCard({ className, deployment, infrastructure }) {
    return (
        <Card className={cn(className, "flex flex-col justify-between")}>
            <CardHeader className="flex flex-row items-start justify-between">
                <div>
                    <CardTitle>Deployment Status</CardTitle>
                    <CardDescription
                        className="text-xs text-muted-foreground mt-1.5"
                        suppressHydrationWarning
                    >
                        Updated:{" "}
                        {deployment.updated
                            ? new Date(deployment.updated).toISOString()
                            : "Never"}
                    </CardDescription>
                </div>
                {(() => {
                    switch (deployment?.status) {
                        case "ready-to-prepare":
                        case "ready-to-deploy":
                        case "ready-to-configure":
                            return (
                                <Tag className="self-start" color={"blue"}>
                                    {deployment?.status}
                                </Tag>
                            );
                        case "preparing":
                        case "deploying":
                        case "configuring":
                            return (
                                <Tag className="self-start" color={"gray"}>
                                    {deployment?.status}
                                </Tag>
                            );
                        case "live":
                            return (
                                <Tag className="self-start" color={"green"}>
                                    {deployment?.status}
                                </Tag>
                            );
                        case "failed":
                        case "destroying":
                            return (
                                <Tag className="self-start" color={"red"}>
                                    {deployment?.status}
                                </Tag>
                            );
                    }
                })()}
            </CardHeader>
            <CardContent className="flex-1">
                <div className="h-full flex flex-col justify-between border-l ml-2">
                    {["ready-to-prepare", "preparing"].includes(
                        deployment?.status,
                    ) ? (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleDashed className="h-4" /> Prepared
                        </div>
                    ) : deployment?.status === "ready-to-deploy" ? (
                        <div className="bg-background flex flex-row gap-2 items-center -translate-x-3">
                            <CircleCheck className="h-4" /> Prepared
                        </div>
                    ) : (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleCheck className="h-4" /> Prepared
                        </div>
                    )}

                    {[
                        "ready-to-prepare",
                        "preparing",
                        "ready-to-deploy",
                    ].includes(deployment?.status) ? (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleDashed className="h-4" /> Deploying
                        </div>
                    ) : deployment?.status === "deploying" ? (
                        <div className="bg-background flex flex-row gap-2 items-center -translate-x-3">
                            <Circle className="h-4" /> Deploying
                        </div>
                    ) : (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleCheck className="h-4" /> Deploying
                        </div>
                    )}
                    {[
                        "ready-to-prepare",
                        "preparing",
                        "ready-to-deploy",
                        "deploying",
                    ].includes(deployment?.status) ? (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleDashed className="h-4" /> Deployed
                        </div>
                    ) : deployment?.status === "ready-to-configure" ? (
                        <div className="bg-background flex flex-row gap-2 items-center -translate-x-3">
                            <CircleCheck className="h-4" /> Deployed
                        </div>
                    ) : (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleCheck className="h-4" /> Deployed
                        </div>
                    )}

                    {[
                        "ready-to-prepare",
                        "preparing",
                        "ready-to-deploy",
                        "deploying",
                        "ready-to-configure",
                    ].includes(deployment?.status) ? (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleDashed className="h-4" /> Configuring
                        </div>
                    ) : deployment?.status === "configuring" ? (
                        <div className="bg-background flex flex-row gap-2 items-center -translate-x-3">
                            <Circle className="h-4" /> Configuring
                        </div>
                    ) : (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleCheck className="h-4" /> Configuring
                        </div>
                    )}
                    {[
                        "ready-to-prepare",
                        "preparing",
                        "ready-to-deploy",
                        "deploying",
                        "ready-to-configure",
                        "configuring",
                    ].includes(deployment?.status) ? (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleDashed className="h-4" /> Configured
                        </div>
                    ) : deployment?.status === "live" ? (
                        <div className="bg-background flex flex-row gap-2 items-center -translate-x-3">
                            <CircleCheck className="h-4" /> Configured
                        </div>
                    ) : (
                        <div className="bg-background flex flex-row gap-2 items-center text-muted-foreground -translate-x-3">
                            <CircleCheck className="h-4" /> Configured
                        </div>
                    )}
                </div>
            </CardContent>
            <CardFooter>
                <div className="flex w-full flex-row justify-between items-center">
                    <div className="flex gap-2 flex-row">
                        {(() => {
                            const hasConfigurations = infrastructure.some(
                                (i) =>
                                    i.configurations !== null &&
                                    i.configurations.length > 0,
                            );

                            const resources = infrastructure.flatMap(
                                (i) => i.resources,
                            );

                            const hasTailscaleIps = resources.every(
                                (resource) => {
                                    // Only care about aws_instance or digitalocean_droplet
                                    if (
                                        resource.resourceType ===
                                            "aws_instance" ||
                                        resource.resourceType ===
                                            "digitalocean_droplet"
                                    ) {
                                        return !!resource.tailscaleIp; // must have tailscaleIp
                                    }
                                    return true; // other types are ignored
                                },
                            );

                            switch (deployment?.status) {
                                case "ready-to-prepare":
                                    return (
                                        <Button
                                            onClick={() =>
                                                prepareDeployment(
                                                    deployment?.id,
                                                )
                                            }
                                            size="sm"
                                        >
                                            Prepare
                                        </Button>
                                    );
                                case "preparing":
                                    return (
                                        <Button disabled size="sm">
                                            Prepare
                                        </Button>
                                    );
                                case "ready-to-deploy":
                                    return (
                                        <Button
                                            onClick={() =>
                                                deployDeployment(deployment?.id)
                                            }
                                            disabled={
                                                infrastructure.filter(
                                                    (i) =>
                                                        i.status !== "default",
                                                ).length < 1
                                            }
                                            size="sm"
                                        >
                                            Deploy
                                        </Button>
                                    );
                                case "deploying":
                                    return (
                                        <Button disabled size="sm">
                                            Deploy
                                        </Button>
                                    );
                                case "ready-to-configure":
                                case "live":
                                case "failed":
                                    return (
                                        <TooltipProvider>
                                            <Button
                                                variant="secondary"
                                                size="sm"
                                                onClick={() =>
                                                    deployDeployment(
                                                        deployment?.id,
                                                    )
                                                }
                                                disabled={
                                                    infrastructure.filter(
                                                        (i) =>
                                                            i.status !==
                                                            "default",
                                                    ).length < 1
                                                }
                                            >
                                                <Undo2 /> Deploy
                                            </Button>

                                            {!hasConfigurations ||
                                            !hasTailscaleIps ? (
                                                <Tooltip delayDuration={25}>
                                                    <TooltipTrigger>
                                                        <Button
                                                            size="sm"
                                                            disabled
                                                        >
                                                            Configure
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        {!hasConfigurations
                                                            ? "Add configurations to infrastructure first."
                                                            : "Waiting for Tailscale IPs to be assigned..."}
                                                    </TooltipContent>
                                                </Tooltip>
                                            ) : (
                                                <Button
                                                    onClick={() =>
                                                        configureDeployment(
                                                            deployment?.id,
                                                        )
                                                    }
                                                    size="sm"
                                                    disabled={
                                                        !hasConfigurations ||
                                                        !hasTailscaleIps
                                                    }
                                                >
                                                    Configure
                                                </Button>
                                            )}
                                        </TooltipProvider>
                                    );
                                case "configuring":
                                case "destroying":
                                    return (
                                        <>
                                            <Button
                                                variant="secondary"
                                                size="sm"
                                                disabled
                                            >
                                                <Undo2 /> Deploy
                                            </Button>
                                            <Button size="sm" disabled>
                                                Configure
                                            </Button>
                                        </>
                                    );
                            }
                        })()}
                    </div>
                    <div className="flex flex-row gap-2">
                        <RefreshButton />
                        <LogDialog log={deployment?.log} />
                    </div>
                </div>
            </CardFooter>
        </Card>
    );
}
