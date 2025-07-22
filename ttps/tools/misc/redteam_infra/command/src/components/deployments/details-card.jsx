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
import { Textarea } from "../ui/textarea";

export function DetailsCard({ className, deployment }) {
    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Deployment Details</CardTitle>
                    <CardDescription className="text-xs text-muted-foreground mt-1.5">
                        View and modify the details of this deployment.
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
                        <Label>Name</Label>
                        <Input
                            className=""
                            value={deployment.name}
                            placeholder="Example Deployment"
                            disabled
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label>Region</Label>
                        <Input
                            className=""
                            value={deployment.region}
                            placeholder="Example Deployment"
                            disabled
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label>Description</Label>
                        <Textarea
                            className=""
                            value={deployment.description}
                            placeholder=""
                            disabled
                        />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
