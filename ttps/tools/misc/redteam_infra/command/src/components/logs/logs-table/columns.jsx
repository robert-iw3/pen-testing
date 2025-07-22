"use client";

import { DataTableColumnHeader } from "./column-header";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";
import { Tag } from "@/components/common/tag";

export const columns = [
    {
        accessorKey: "source",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Source" />
        ),
        cell: ({ row }) => <Tag>{row.original?.source}</Tag>,
    },
    {
        accessorKey: "timestamp",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Timestamp" />
        ),
        cell: ({ row }) => (
            <p className="min-w-[185px]">{row.original?.timestamp}</p>
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
                case "info":
                case "unknown":
                    return (
                        <Tag className="self-start" color={"gray"}>
                            {status}
                        </Tag>
                    );
                case "warning":
                    return (
                        <Tag className="self-start" color={"amber"}>
                            {status}
                        </Tag>
                    );
                case "error":
                    return (
                        <Tag className="self-start" color={"red"}>
                            {status}
                        </Tag>
                    );
            }
        },
    },
    {
        accessorKey: "message",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Message" />
        ),
        cell: ({ row }) => (
            // TODO: Fix log overflow issue
            <div className="max-w-[1000px] text-overflow-x-wrap">
                <TooltipProvider>
                    <Tooltip>
                        <TooltipTrigger>
                            <p className="font-mono line-clamp-3 text-left max-w-[1000px]">
                                {row.original?.message}
                            </p>
                        </TooltipTrigger>
                        <TooltipContent>
                            <p className="font-mono max-w-[600px]">
                                {row.original?.message}
                            </p>
                        </TooltipContent>
                    </Tooltip>
                </TooltipProvider>
            </div>
        ),
    },
];
