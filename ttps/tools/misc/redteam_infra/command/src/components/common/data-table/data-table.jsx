"use client";

import {
    flexRender,
    getCoreRowModel,
    useReactTable,
    getPaginationRowModel,
    getSortedRowModel,
    getFilteredRowModel,
} from "@tanstack/react-table";
import {
    DropdownMenu,
    DropdownMenuCheckboxItem,
    DropdownMenuContent,
    DropdownMenuTrigger,
    DropdownMenuLabel,
    DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Settings } from "lucide-react";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { DataTablePagination } from "./table-pagination";
import { DataTableSearch } from "./search";

import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";

export function DataTable({
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
    const [pagination, setPagination] = useState({
        pageIndex: 0, //initial page index
        pageSize: 10, //default page size
    });

    const defaultFilterArray = archivable
        ? [{ id: "state", value: false }]
        : [];
    const [columnFilters, setColumnFilters] = useState(defaultFilterArray);
    const [rowSelection, setRowSelection] = useState({});

    const table = useReactTable({
        data,
        columns,
        getCoreRowModel: getCoreRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        onSortingChange: setSorting,
        onPaginationChange: setPagination,
        getSortedRowModel: getSortedRowModel(),
        onColumnFiltersChange: setColumnFilters,
        getFilteredRowModel: getFilteredRowModel(),
        onRowSelectionChange: setRowSelection,
        state: {
            sorting,
            columnFilters,
            pagination,
            rowSelection,
        },
    });

    const router = useRouter();

    const handleRedirect = (id) => {
        const dynamicUrl = redirectTemplate.replace("{id}", id);
        router.push(dynamicUrl);
    };

    return (
        <div className="flex flex-col gap-4 h-full overflow-x-hidden justify-between">
            <div className="flex flex-row justify-between">
                {search && (
                    <DataTableSearch
                        table={table}
                        column={searchColumn}
                        placeholder={searchPlaceholder}
                        setPagination={setPagination}
                    />
                )}
                <div className="flex gap-2">
                    {showOptions && (
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button
                                    variant="outline"
                                    size="icon"
                                    className="ml-auto"
                                >
                                    <Settings className="h-4" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                                {archivable && (
                                    <>
                                        <DropdownMenuLabel>
                                            Settings
                                        </DropdownMenuLabel>
                                        <DropdownMenuCheckboxItem
                                            className="capitalize"
                                            checked={table
                                                .getColumn("state")
                                                ?.getFilterValue()}
                                            onCheckedChange={(value) =>
                                                table
                                                    .getColumn("state")
                                                    ?.setFilterValue(value)
                                            }
                                        >
                                            Show Archived
                                        </DropdownMenuCheckboxItem>
                                        <DropdownMenuSeparator />
                                    </>
                                )}

                                <DropdownMenuLabel>
                                    Toggle columns
                                </DropdownMenuLabel>
                                {table
                                    .getAllColumns()
                                    .filter((column) => column.getCanHide())
                                    .map((column) => {
                                        if (column.id !== "actions")
                                            return (
                                                <DropdownMenuCheckboxItem
                                                    key={column.id}
                                                    className="capitalize"
                                                    checked={column.getIsVisible()}
                                                    onCheckedChange={(value) =>
                                                        column.toggleVisibility(
                                                            !!value,
                                                        )
                                                    }
                                                >
                                                    {column.id}
                                                </DropdownMenuCheckboxItem>
                                            );
                                    })}
                            </DropdownMenuContent>
                        </DropdownMenu>
                    )}

                    {buttonComponent}
                </div>
            </div>
            <div className="rounded-md border overflow-auto flex-1 min-h-0">
                <Table>
                    <TableHeader>
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
                                            onClick={(e) =>
                                                cell.column.id == "actions"
                                                    ? null
                                                    : redirectTemplate
                                                      ? handleRedirect(
                                                            row.original.id,
                                                        )
                                                      : e.preventDefault()
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
            <DataTablePagination table={table} />
        </div>
    );
}
