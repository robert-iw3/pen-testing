"use client";

import {
    flexRender,
    getCoreRowModel,
    useReactTable,
    getPaginationRowModel,
    getSortedRowModel,
    getFilteredRowModel,
} from "@tanstack/react-table";
import { LogTableFacetedFilters } from "./log-filters";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { DataTableSearch } from "./search";

import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";

export function LogsTable({
    columns,
    data,
    buttonComponent,
    redirectTemplate,
    search,
    searchPlaceholder,
    searchColumn,
    showOptions,
    archivable,
}) {
    const [sorting, setSorting] = useState([]);

    const defaultFilterArray = archivable
        ? [{ id: "state", value: false }]
        : [];
    const [columnFilters, setColumnFilters] = useState(defaultFilterArray);
    const [rowSelection, setRowSelection] = useState({});
    const [pagination, setPagination] = useState({
        pageIndex: 0, //initial page index
        pageSize: data.length, //default page size
    });

    const table = useReactTable({
        data,
        columns,
        getCoreRowModel: getCoreRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        onPaginationChange: setPagination,
        onSortingChange: setSorting,
        getSortedRowModel: getSortedRowModel(),
        onColumnFiltersChange: setColumnFilters,
        getFilteredRowModel: getFilteredRowModel(),
        onRowSelectionChange: setRowSelection,
        state: {
            sorting,
            columnFilters,
            rowSelection,
            pagination,
        },
    });

    const router = useRouter();

    const handleRedirect = (id) => {
        const dynamicUrl = redirectTemplate.replace("{id}", id);
        router.push(dynamicUrl);
    };

    return (
        <div className="flex flex-col gap-4 w-full h-full overflow-hidden justify-between">
            <div className="flex flex-row justify-between">
                {search && (
                    <DataTableSearch
                        table={table}
                        column={searchColumn}
                        placeholder={searchPlaceholder}
                    />
                )}
                <div className="flex gap-2">
                    <LogTableFacetedFilters table={table} />
                </div>
            </div>
            {/* Restrict width and allow horizontal scrolling if necessary */}
            <div className="rounded-md border overflow-y-auto overflow-x-auto flex-1 min-h-0 w-full">
                <Table>
                    <TableHeader className="sticky top-0">
                        {table.getHeaderGroups().map((headerGroup) => (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map((header) => {
                                    return (
                                        <TableHead key={header.id}>
                                            {header.isPlaceholder
                                                ? null
                                                : flexRender(
                                                      header.column.columnDef
                                                          .header,
                                                      header.getContext(),
                                                  )}
                                        </TableHead>
                                    );
                                })}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows?.length ? (
                            table.getRowModel().rows.map((row) => (
                                <TableRow
                                    key={row.id}
                                    data-state={
                                        row.getIsSelected() && "selected"
                                    }
                                    className={
                                        redirectTemplate ? "cursor-pointer" : ""
                                    }
                                >
                                    {row.getVisibleCells().map((cell) => (
                                        <TableCell
                                            key={cell.id}
                                            onClick={() =>
                                                cell.column.id == "actions"
                                                    ? null
                                                    : redirectTemplate
                                                      ? handleRedirect(
                                                            row.original.id,
                                                        )
                                                      : null
                                            }
                                        >
                                            {flexRender(
                                                cell.column.columnDef.cell,
                                                cell.getContext(),
                                            )}
                                        </TableCell>
                                    ))}
                                </TableRow>
                            ))
                        ) : (
                            <TableRow>
                                <TableCell
                                    colSpan={columns.length}
                                    className="text-center h-16"
                                >
                                    No results.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>
        </div>
    );
}
