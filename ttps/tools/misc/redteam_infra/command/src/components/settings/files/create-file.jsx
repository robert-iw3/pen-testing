"use client";

import { Button } from "@/components/ui/button";
import { useState } from "react";
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
    DialogTrigger,
    DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { FileEditor } from "./editor";
import { addFile } from "@/actions/files";
import { Separator } from "@/components/ui/separator";
import { fileVariableTypes } from "@/lib/template-variables";

export function CreateFile() {
    const [dialogOpen, setDialogOpen] = useState(false);

    const [name, setName] = useState("");
    const [nameError, setNameError] = useState(false);

    const [extension, setExtension] = useState("");
    const [extensionError, setExtensionError] = useState(false);

    const [value, setValue] = useState("");
    const [valueError, setValueError] = useState(false);

    const [variables, setVariables] = useState([]);
    const [variablesError, setVariablesError] = useState(false);

    const addFileHandler = async () => {
        if (!name) return setNameError(true);
        setNameError(false);

        if (!extension) return setExtensionError(true);
        setExtensionError(false);

        if (!value) return setValueError(true);
        setValueError(false);

        // TODO: detect if varibale error true

        const result = await addFile(name, extension, value, variables);
        if (result) {
            setDialogOpen(false);
            setName("");
            setNameError(false);
            setExtension("");
            setExtensionError(false);
            setValue("");
            setValueError(false);
            setVariables([]);
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

    const setDialogOpenHandler = (value) => {
        setDialogOpen(value);
    };

    return (
        <Dialog open={dialogOpen} onOpenChange={setDialogOpenHandler}>
            <DialogTrigger asChild>
                <Button>Create File</Button>
            </DialogTrigger>
            <DialogContent className="min-w-[750px]">
                <DialogHeader>
                    <DialogTitle>Create File</DialogTitle>
                    <DialogDescription>
                        Use the form below to create a new file. Required fields
                        are marked with an asterisk.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                    <div className="gap-2 flex flex-row w-full">
                        <div className="flex flex-1 flex-col gap-2">
                            <Label htmlFor="name">Name*</Label>
                            <Input
                                id="name"
                                placeholder="nginx-default"
                                value={name}
                                className={
                                    nameError ? "border border-red-500" : ""
                                }
                                onChange={(e) => setName(e.target.value)}
                            />
                        </div>
                        <p className="self-end">.</p>
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="name">Extension*</Label>

                            <Input
                                id="name"
                                placeholder="conf"
                                value={extension}
                                className={
                                    extensionError
                                        ? "border border-red-500"
                                        : ""
                                }
                                onChange={(e) => setExtension(e.target.value)}
                            />
                        </div>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="name">Value*</Label>
                        <FileEditor
                            code={value}
                            setCode={(v) => {
                                setValue(v);
                                extractVariables(v);
                            }}
                        />
                    </div>
                    <div className="grid gap-2 max-h-[230px] overflow-y-auto">
                        {variables.map((variable) => (
                            <div key={variable.name}>
                                <div className="py-2 flex w-full justify-between flex-row">
                                    <div>
                                        <Label>Variable Name*</Label>
                                        <Input disabled value={variable.name} />
                                    </div>
                                    <div>
                                        <Label>Variable Type*</Label>
                                        <Select
                                            onValueChange={(value) => {
                                                let newVariables = variables;

                                                newVariables = newVariables.map(
                                                    (v) =>
                                                        v.name === variable.name
                                                            ? {
                                                                  ...v,
                                                                  type: value,
                                                              }
                                                            : v,
                                                );

                                                setVariables([...newVariables]);
                                            }}
                                        >
                                            <SelectTrigger className="w-[250px]">
                                                <SelectValue placeholder="Type" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                {fileVariableTypes.map(
                                                    (type) => (
                                                        <SelectItem
                                                            key={type.value}
                                                            value={type.value}
                                                        >
                                                            {type.label}
                                                        </SelectItem>
                                                    ),
                                                )}
                                            </SelectContent>
                                        </Select>
                                    </div>
                                </div>
                                <Separator />
                            </div>
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
                            extension == "" ||
                            value == "" ||
                            variables.some((v) => !v.type)
                        }
                        onClick={() => addFileHandler()}
                    >
                        Create
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
