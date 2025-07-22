"use client";

import { DataTableColumnHeader } from "@/components/common/data-table/column-header";
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
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { YamlEditor } from "./editor";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { deleteTemplate, updateTemplate } from "@/actions/templates";
import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useState } from "react";
import { configurationVariableTypes } from "@/lib/template-variables";

export const columns = [
    {
        accessorKey: "name",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Name" />
        ),
    },
    {
        id: "variables",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Variables" />
        ),
        cell: ({ row }) => {
            return row.original.variables?.length || 0;
        },
    },
    {
        id: "actions",
        cell: function Cell({ row }) {
            const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
            const [editDialogOpen, setEditDialogOpen] = useState(false);
            const [name, setName] = useState(row.original.name ?? "");
            const [nameError, setNameError] = useState(false);

            const [code, setCode] = useState(row.original.value ?? "");
            const [codeError, setCodeError] = useState(false);

            const [variables, setVariables] = useState(
                row.original.variables ?? [],
            );
            const [variablesError, setVariablesError] = useState(false);

            const addTemplateHandler = async () => {
                if (!name) return setNameError(true);
                setNameError(false);

                if (!code) return setCodeError(true);
                setCodeError(false);

                // TODO: detect if varibale error true

                const result = await updateTemplate(
                    row.original.id,
                    name,
                    code,
                    variables,
                );
                if (result) {
                    setEditDialogOpen(false);
                    setName(result[0].name);
                    setNameError(false);
                    setCode(result[0].value);
                    setCodeError(false);
                    setVariables([...result[0].variables]);
                    setVariablesError(false);
                }
            };

            const extractVariables = (code) => {
                // Regular expression to match custom variables surrounded by $$
                const variableRegex = /\$\$(.*?)\$\$/g;
                const detectedVariables = [];

                // Extract all matches
                let match;
                while ((match = variableRegex.exec(code)) !== null) {
                    if (!detectedVariables.some((v) => v.name === match[1]))
                        detectedVariables.push({
                            name: match[1],
                            type: "",
                        });
                }

                return setVariables(detectedVariables);
            };
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
                                    Deleting a configuration template will
                                    permanently remove it.
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
                                            deleteTemplate(row.original.id);
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
                    <Dialog
                        open={editDialogOpen}
                        onOpenChange={setEditDialogOpen}
                    >
                        <DialogContent className="min-w-[750px]">
                            <DialogHeader>
                                <DialogTitle>
                                    Update Configuration Template
                                </DialogTitle>
                                <DialogDescription>
                                    Modify your Ansible configuration below to
                                    update a configuration template. Required
                                    fields are marked with an asterisk.
                                </DialogDescription>
                            </DialogHeader>
                            <div className="grid gap-4">
                                <div className="grid gap-2">
                                    <Label htmlFor="name">Name*</Label>
                                    <Input
                                        id="name"
                                        placeholder="AWS Subnets"
                                        value={name}
                                        className={
                                            nameError
                                                ? "border border-red-500"
                                                : ""
                                        }
                                        onChange={(e) =>
                                            setName(e.target.value)
                                        }
                                    />
                                </div>
                                <div className="grid gap-2">
                                    <Label htmlFor="name">Template*</Label>
                                    <YamlEditor
                                        code={code}
                                        setCode={(value) => {
                                            setCode(value);
                                            extractVariables(value);
                                        }}
                                    />
                                </div>
                                <div className="grid gap-2 max-h-[230px] overflow-y-auto">
                                    {variables.map((variable) => (
                                        <>
                                            <div
                                                key={variable.name}
                                                className="py-2 flex w-full justify-between flex-row"
                                            >
                                                <div>
                                                    <Label>
                                                        Variable Name*
                                                    </Label>
                                                    <Input
                                                        disabled
                                                        value={variable.name}
                                                    />
                                                </div>
                                                <div>
                                                    <Label>
                                                        Variable Type*
                                                    </Label>
                                                    <Select
                                                        onValueChange={(
                                                            value,
                                                        ) => {
                                                            let newVariables =
                                                                variables;

                                                            newVariables =
                                                                newVariables.map(
                                                                    (v) =>
                                                                        v.name ===
                                                                        variable.name
                                                                            ? {
                                                                                  ...v,
                                                                                  type: value,
                                                                              }
                                                                            : v,
                                                                );

                                                            setVariables([
                                                                ...newVariables,
                                                            ]);
                                                        }}
                                                        defaultValue={
                                                            variable.type
                                                        }
                                                    >
                                                        <SelectTrigger className="w-[250px]">
                                                            <SelectValue placeholder="Type" />
                                                        </SelectTrigger>
                                                        <SelectContent>
                                                            {configurationVariableTypes.map(
                                                                (type) => (
                                                                    <SelectItem
                                                                        key={
                                                                            type.value
                                                                        }
                                                                        value={
                                                                            type.value
                                                                        }
                                                                    >
                                                                        {
                                                                            type.label
                                                                        }
                                                                    </SelectItem>
                                                                ),
                                                            )}
                                                        </SelectContent>
                                                    </Select>
                                                </div>
                                            </div>
                                            <Separator />
                                        </>
                                    ))}
                                    <p className="text-sm text-red-500">
                                        {variablesError
                                            ? "Please select a type for all variables."
                                            : null}
                                    </p>
                                </div>
                            </div>
                            <DialogFooter>
                                <Button
                                    type="button"
                                    disabled={
                                        name == "" ||
                                        code == "" ||
                                        variables.some((v) => !v.type)
                                    }
                                    onClick={() => addTemplateHandler()}
                                >
                                    Update
                                </Button>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                    <DropdownMenu modal={false}>
                        <DropdownMenuTrigger asChild>
                            <Button variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Open menu</span>
                                <MoreHorizontal className="h-4 w-4" />
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            <DropdownMenuItem
                                onClick={(e) => {
                                    setEditDialogOpen(true);
                                }}
                            >
                                Edit
                            </DropdownMenuItem>
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
            );
        },
    },
];
