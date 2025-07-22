"use client";

import { DataTableColumnHeader } from "../common/data-table/column-header";
import { MoreHorizontal } from "lucide-react";
import { Checkbox } from "../ui/checkbox";
import {
    archiveDomain,
    deleteDomain,
    quickUpdateAutoScan,
    unarchiveDomain,
} from "@/actions/domains";
import { deleteDnsRecord } from "@/actions/dns";
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

export const columns = [
    {
        accessorKey: "domain",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Domain" />
        ),
    },
    {
        accessorKey: "state",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="State" />
        ),
        cell: ({ row }) => {
            const state = row.getValue("state");
            switch (state) {
                case "pending-analysis":
                    return <Tag color={"purple"}>{state}</Tag>;
                case "healthy":
                    return <Tag color={"green"}>{state}</Tag>;
                case "unhealthy":
                    return <Tag color={"amber"}>{state}</Tag>;
                case "burnt":
                    return <Tag color={"red"}>{state}</Tag>;
                case "aging":
                    return <Tag color={"blue"}>{state}</Tag>;
                case "archived":
                    return <Tag color={"gray"}>{state}</Tag>;
            }
        },
        filterFn: (row, id, value) => {
            const state = row.getValue("state");
            return value ? row : state !== "archived";
        },
    },
    {
        accessorKey: "category",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Category" />
        ),
        cell: ({ row }) => {
            const category = row.getValue("category");
            return <p className="capitalize">{category}</p>;
        },
    },
    {
        accessorKey: "updated",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Last Updated" />
        ),
        cell: ({ row }) => {
            const updated = row.getValue("updated");
            return (
                <p className="capitalize" suppressHydrationWarning>
                    {updated ? new Date(updated).toLocaleString() : "Never"}
                </p>
            );
        },
    },
    {
        id: "actions",
        cell: function Cell({ row }) {
            const router = useRouter();
            const [archiveDialogOpen, setArchiveDialogOpen] = useState(false);
            const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

            return (
                <>
                    <AlertDialog
                        open={archiveDialogOpen}
                        onOpenChange={setArchiveDialogOpen}
                    >
                        <AlertDialogContent>
                            <AlertDialogHeader>
                                <AlertDialogTitle>
                                    Are you absolutely sure?
                                </AlertDialogTitle>
                                <AlertDialogDescription>
                                    Archiving a domain will hide it from your
                                    dashboard and disable autoscan. Archived
                                    domains can be recovered.
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
                                            archiveDomain(
                                                row.original.id,
                                                row.original.projectId,
                                            );
                                            setArchiveDialogOpen(false);
                                        }}
                                        className="h-9"
                                    >
                                        Archive
                                    </Button>
                                </AlertDialogAction>
                            </AlertDialogFooter>
                        </AlertDialogContent>
                    </AlertDialog>
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
                                    Deleting a domain will permanently remove it
                                    and all associated data.
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
                                            deleteDomain(
                                                row.original.id,
                                                row.original.projectId,
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
                            {row.original.state !== "archived" && (
                                <>
                                    <DropdownMenuItem
                                        onClick={() =>
                                            router.push(
                                                `/dashboard/domains/${row.original.id}`,
                                            )
                                        }
                                    >
                                        More Information
                                    </DropdownMenuItem>
                                    {row.original?.projectId && (
                                        <DropdownMenuItem
                                            onClick={() => {
                                                router.push(
                                                    `/dashboard/${row.original.projectId}/overview`,
                                                );
                                            }}
                                        >
                                            View project
                                        </DropdownMenuItem>
                                    )}
                                    {row.original?.stateAutoScan ? (
                                        <DropdownMenuItem
                                            onClick={() => {
                                                quickUpdateAutoScan(
                                                    row.original.id,
                                                    row.original.projectId,
                                                    false,
                                                );
                                            }}
                                        >
                                            Disable Auto Scan
                                        </DropdownMenuItem>
                                    ) : (
                                        <DropdownMenuItem
                                            onClick={() => {
                                                quickUpdateAutoScan(
                                                    row.original.id,
                                                    row.original.projectId,
                                                    true,
                                                );
                                            }}
                                        >
                                            Enable Auto Scan
                                        </DropdownMenuItem>
                                    )}
                                    <DropdownMenuSeparator />
                                </>
                            )}
                            {row.original.state === "archived" ? (
                                <DropdownMenuItem
                                    onClick={() => {
                                        unarchiveDomain(
                                            row.original.id,
                                            row.original.projectId,
                                        );
                                    }}
                                >
                                    Unarchive
                                </DropdownMenuItem>
                            ) : (
                                <DropdownMenuItem
                                    onClick={() => setArchiveDialogOpen(true)}
                                >
                                    Archive
                                </DropdownMenuItem>
                            )}

                            <DropdownMenuItem
                                className="text-red-500"
                                onClick={() => setDeleteDialogOpen(true)}
                            >
                                Delete
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </>
            );
        },
    },
];

export const dnsColumns = [
    {
        accessorKey: "name",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Name" />
        ),
    },
    {
        accessorKey: "value",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Value" />
        ),
        cell: ({ row }) => {
            return <p className="break-all">{row.original.value}</p>;
        },
    },
    {
        id: "actions",
        cell: function Cell({ row }) {
            const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
            const router = useRouter();
            return (
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
                                    Deleting a DNS record will permanently
                                    remove it and all associated data.
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
                                            deleteDnsRecord(
                                                row.original.domainId,
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
                            <DropdownMenuItem
                                className="text-red-500"
                                onClick={() => {
                                    setDeleteDialogOpen(true);
                                }}
                            >
                                Remove
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </>
            );
        },
    },
];
