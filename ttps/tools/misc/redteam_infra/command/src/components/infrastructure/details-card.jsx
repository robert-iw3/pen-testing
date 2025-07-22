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
import { Input } from "../ui/input";
import { Textarea } from "../ui/textarea";
import { Tag } from "../common/tag";

export function DetailsCard({ className, infrastructure, templates }) {
    const status = infrastructure.status;
    var template = templates.find(
        (t) => t.id === infrastructure.infrastructureTemplateId,
    );

    if (!template)
        template =
            infrastructure.status === "default"
                ? { name: "Default Infrastructure" }
                : { name: "Unknown" };

    const StatusTag = () => {
        switch (status) {
            case "stopped":
                return (
                    <Tag className="self-start" color={"red"}>
                        {status}
                    </Tag>
                );
            case "building":
            case "configuring":
            case "stopping":
            case "default":
                return (
                    <Tag className="self-start" color={"gray"}>
                        {status}
                    </Tag>
                );
            case "running":
                return (
                    <Tag className="self-start" color={"green"}>
                        {status}
                    </Tag>
                );
            case "pending":
                return (
                    <Tag className="self-start" color={"blue"}>
                        {status}
                    </Tag>
                );
        }
    };

    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Infrastructure Details</CardTitle>
                    <CardDescription className="text-xs text-muted-foreground mt-1.5">
                        View and modify the details of this infrastructure.
                    </CardDescription>
                </div>
                <div className="flex items-center" style={{ marginTop: 0 }}>
                    <StatusTag />
                </div>
            </CardHeader>
            <CardContent>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Label>Name</Label>
                        <Input
                            value={infrastructure.name}
                            placeholder="Example Redirector"
                            disabled
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label>Template</Label>
                        <Input
                            value={template.name}
                            placeholder="HTTP Redirector"
                            disabled
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label>Description</Label>
                        <Textarea
                            value={infrastructure.description}
                            placeholder=""
                            disabled
                        />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
