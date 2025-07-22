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
import { useState } from "react";

export function DetailsCard({ className, domain }) {
    const [isEditing, setIsEditing] = useState(false);
    const [changesMade, setChangesMade] = useState(false);

    const [category, setCategory] = useState(domain?.category);
    const handleCategoryChange = (value) => {
        setCategory(value);
        setChangesMade(true);
    };

    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Domain Details</CardTitle>
                    <CardDescription
                        className="text-xs text-muted-foreground mt-1.5"
                        suppressHydrationWarning
                    >
                        Updated:{" "}
                        {domain.updated
                            ? new Date(domain.updated).toISOString()
                            : "Never"}
                    </CardDescription>
                </div>
                <div className="flex items-center" style={{ marginTop: 0 }}>
                    {/* {!isEditing ? (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setIsEditing(true)}
            >
              Edit
            </Button>
          ) : (
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setIsEditing(false)}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => handleSubmit()}
                disabled={!changesMade}
              >
                Save
              </Button>
            </div>
          )} */}
                </div>
            </CardHeader>
            <CardContent>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Label>Domain</Label>
                        <Input
                            className=""
                            value={domain.domain}
                            placeholder="example.com"
                            disabled
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label>Reputation Category</Label>
                        <Input
                            className="capitalize"
                            value={category}
                            onChange={(e) =>
                                handleCategoryChange(e.target.value)
                            }
                            placeholder="finance"
                            disabled={!isEditing || domain.stateAutoScan}
                        />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
