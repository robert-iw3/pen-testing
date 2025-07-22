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
import { deleteDeployment } from "@/actions/deployments";
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

export function DangerCard({ className, deployment }) {
    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Danger Zone</CardTitle>
                    <CardDescription
                        className="text-xs text-muted-foreground mt-1.5"
                        suppressHydrationWarning
                    >
                        Warning, these actions are irreversable.
                    </CardDescription>
                </div>
            </CardHeader>
            <CardContent></CardContent>
            <CardFooter>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <AlertDialog>
                            <AlertDialogTrigger asChild>
                                <Button size="sm" variant={"destructive"}>
                                    Delete Deployment
                                </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                                <AlertDialogHeader>
                                    <AlertDialogTitle>
                                        Are you absolutely sure?
                                    </AlertDialogTitle>
                                    <AlertDialogDescription>
                                        Deleting a deployment will permanently
                                        destroy it and all associated
                                        infrastructure.
                                    </AlertDialogDescription>
                                </AlertDialogHeader>
                                {/* TODO: Please type the name of the deployment to continue... */}
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
                                                deleteDeployment(deployment.id)
                                            }
                                            className="h-9"
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
