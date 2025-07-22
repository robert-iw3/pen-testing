"use client";

import { cn } from "@/lib/utils";
import {
    Card,
    CardHeader,
    CardTitle,
    CardContent,
    CardDescription,
    CardFooter,
} from "../ui/card";
import { Button } from "../ui/button";
import { deleteProject } from "@/actions/projects";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { useState } from "react";

export function DangerCard({ className, project, hasDeployments }) {
    const [deploymentsError, setDeploymentsError] = useState(false);

    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Danger Zone</CardTitle>
                    <CardDescription className="text-xs text-muted-foreground mt-1.5">
                        Warning, these actions are irreversable.
                    </CardDescription>
                </div>
            </CardHeader>
            <CardContent>
                {deploymentsError && (
                    <p className="text-sm text-red-500">
                        Remove all deployments before deleting this project.
                    </p>
                )}
            </CardContent>
            <CardFooter>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <AlertDialog>
                            <AlertDialogTrigger asChild>
                                <Button
                                    size="sm"
                                    variant={"destructive"}
                                    onClick={(e) => {
                                        if (hasDeployments) {
                                            e.preventDefault();
                                        }

                                        setDeploymentsError(hasDeployments);
                                    }}
                                >
                                    Delete Project
                                </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                                <AlertDialogHeader>
                                    <AlertDialogTitle>
                                        Are you absolutely sure?
                                    </AlertDialogTitle>
                                    <AlertDialogDescription>
                                        Deleting a project will permanently
                                        destroy it.
                                    </AlertDialogDescription>
                                </AlertDialogHeader>
                                {/* TODO: Please type the name of the project to continue... */}
                                <AlertDialogFooter>
                                    <AlertDialogCancel asChild>
                                        <Button
                                            className="h-9"
                                            variant="outline"
                                        >
                                            Cancel
                                        </Button>
                                    </AlertDialogCancel>
                                    <AlertDialogAction asChild>
                                        <Button
                                            onClick={() =>
                                                deleteProject(project.id)
                                            }
                                            className="h-9"
                                            disabled={hasDeployments}
                                        >
                                            Delete
                                        </Button>
                                    </AlertDialogAction>
                                </AlertDialogFooter>
                            </AlertDialogContent>
                        </AlertDialog>
                    </div>
                </div>
            </CardFooter>
        </Card>
    );
}
