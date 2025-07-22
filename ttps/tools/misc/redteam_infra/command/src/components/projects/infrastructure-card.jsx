"use client";

import { useMemo } from "react";
import { PieChart, Label, Pie } from "recharts";

import {
    Card,
    CardHeader,
    CardTitle,
    CardContent,
    CardDescription,
} from "../ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "../ui/chart";
import { cn } from "@/lib/utils";

const chartConfig = {
    infrastructure: {
        label: "Infrastructure",
    },
    default: { label: "Default", color: "#78716c" },
    building: { label: "Building", color: "#a8a29e" },
    configuring: { label: "Configuring", color: "#d6d3d1" },
    stopping: { label: "Stopping", color: "#e7e5e4" },
    pending: { label: "Pending", color: "#3b82f6" },
    failed: { label: "Failed", color: "#ef4444" },
    running: { label: "Running", color: "#22c55e" },
};

export function InfrastructureCard({ className, data }) {
    const totalCount = useMemo(() => {
        return data.reduce((acc, total) => acc + total.count, 0);
    }, [data]);

    data.forEach((i) => {
        i.fill = `var(--color-${i.status})`;
    });

    return (
        <Card className={cn(className, "flex flex-col")}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Infrastructure Summary</CardTitle>
                    <CardDescription className="text-xs text-muted-foreground mt-1.5">
                        An overview of the infrastructure deployed for this
                        project.
                    </CardDescription>
                </div>
            </CardHeader>
            <CardContent className="flex-1">
                {totalCount > 0 ? (
                    <ChartContainer
                        config={chartConfig}
                        className="mx-auto aspect-square max-h-[200px]"
                    >
                        <PieChart>
                            <ChartTooltip
                                cursor={false}
                                content={<ChartTooltipContent hideLabel />}
                            />
                            <Pie
                                data={data}
                                dataKey="count"
                                nameKey="status"
                                innerRadius={60}
                                strokeWidth={5}
                            >
                                <Label
                                    content={({ viewBox }) => {
                                        if (
                                            viewBox &&
                                            "cx" in viewBox &&
                                            "cy" in viewBox
                                        ) {
                                            return (
                                                <text
                                                    x={viewBox.cx}
                                                    y={viewBox.cy}
                                                    textAnchor="middle"
                                                    dominantBaseline="middle"
                                                >
                                                    <tspan
                                                        x={viewBox.cx}
                                                        y={viewBox.cy}
                                                        className="fill-foreground text-3xl font-bold"
                                                    >
                                                        {totalCount.toLocaleString()}
                                                    </tspan>
                                                    <tspan
                                                        x={viewBox.cx}
                                                        y={
                                                            (viewBox.cy || 0) +
                                                            24
                                                        }
                                                        className="fill-muted-foreground"
                                                    >
                                                        Total
                                                    </tspan>
                                                </text>
                                            );
                                        }
                                    }}
                                />
                            </Pie>
                        </PieChart>
                    </ChartContainer>
                ) : (
                    <div className="text-sm text-muted-foreground border-dashed flex items-center justify-center h-full w-full border rounded-md">
                        No infrastructure deployed.
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
