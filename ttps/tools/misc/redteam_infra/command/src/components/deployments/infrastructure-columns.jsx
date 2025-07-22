"use client";

import { DataTableColumnHeader } from "../common/data-table/column-header";
import { MoreHorizontal } from "lucide-react";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "@/components/ui/alert-dialog";

import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";

import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tag } from "../common/tag";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { deleteInfrastructure } from "@/actions/infrastructure";

export const columns = () => [
    {
        accessorKey: "name",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Name" />
        ),
    },
    {
        accessorKey: "status",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Status" />
        ),
        cell: ({ row }) => {
            const status = row.getValue("status");

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
        },
    },
    {
        id: "resources",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Resources" />
        ),
        cell: ({ row }) => <p>{row.original.resources.length}</p>,
    },
    {
        id: "privateIp",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Private IP" />
        ),
        cell: function Cell({ row }) {
            var privateIps = row.original.resources.map(
                (resource) => resource.privateIp,
            );

            // Remove duplicate and null values
            privateIps = [...new Set(privateIps)].filter((n) => n);

            if (privateIps.length > 1)
                return (
                    <TooltipProvider>
                        <Tooltip>
                            <TooltipTrigger>
                                <p className="underline decoration-dashed">
                                    Multiple
                                </p>
                            </TooltipTrigger>
                            <TooltipContent>
                                <p className="max-w-[100px]">
                                    {privateIps.join(", ")}
                                </p>
                            </TooltipContent>
                        </Tooltip>
                    </TooltipProvider>
                );
            return <p>{privateIps[0] || "N/A"}</p>;
        },
    },
    {
        id: "publicIp",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Public IP" />
        ),
        cell: function Cell({ row }) {
            var publicIps = row.original.resources.map(
                (resource) => resource.publicIp,
            );

            publicIps = [...new Set(publicIps)].filter((n) => n);

            if (publicIps.length > 1)
                return (
                    <TooltipProvider>
                        <Tooltip>
                            <TooltipTrigger>
                                <p className="underline decoration-dashed">
                                    Multiple
                                </p>
                            </TooltipTrigger>
                            <TooltipContent>
                                <p className="max-w-[100px]">
                                    {publicIps.join(", ")}
                                </p>
                            </TooltipContent>
                        </Tooltip>
                    </TooltipProvider>
                );
            return <p>{publicIps[0] || "N/A"}</p>;
        },
    },
    {
        id: "actions",
        cell: function Cell({ row }) {
            const router = useRouter();
            const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
            return row.original.status !== "default" ? (
                <>
                    <AlertDialog
                        open={deleteDialogOpen}
                        onOpenChange={setDeleteDialogOpen}
                    >
                        <AlertDialogContent>
                            <AlertDialogHeader>
                                <AlertDialogTitle>
                                    Are you absolutely sure?
                                </AlertDialogTitle>
                                <AlertDialogDescription>
                                    Deleting infrastructure will permanently
                                    remove it and all associated resources.
                                </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                                <AlertDialogCancel asChild>
                                    <Button className="h-9" variant="outline">
                                        Cancel
                                    </Button>
                                </AlertDialogCancel>
                                <AlertDialogAction asChild>
                                    <Button
                                        onClick={() => {
                                            deleteInfrastructure(
                                                row.original.deploymentId,
                                                row.original.id,
                                            );
                                            setDeleteDialogOpen(false);
                                        }}
                                        className="h-9"
                                    >
                                        Delete
                                    </Button>
                                </AlertDialogAction>
                            </AlertDialogFooter>
                        </AlertDialogContent>
                    </AlertDialog>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Open menu</span>
                                <MoreHorizontal className="h-4 w-4" />
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem>Copy Public IP</DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                                className="text-red-500"
                                onClick={() => setDeleteDialogOpen(true)}
                            >
                                Delete
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </>
            ) : null;
        },
    },
];
