"use client";

import { cn } from "@/lib/utils";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardDescription,
} from "../ui/card";

export function InfrastuctureCard({ className, domain }) {
  return (
    <Card className={cn(className, "flex flex-col")}>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Infrastucture</CardTitle>
          <CardDescription
            className="text-xs text-muted-foreground mt-1.5"
            suppressHydrationWarning
          >
            Updated:{" "}
            {domain?.updated ? new Date(domain.updated).toISOString() : "Never"}
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="flex-1">
        <div className="w-full h-full border border-dashed rounded-md flex items-center justify-center text-muted-foreground text-sm">
          No infrastucture assigned.
        </div>
      </CardContent>
    </Card>
  );
}
