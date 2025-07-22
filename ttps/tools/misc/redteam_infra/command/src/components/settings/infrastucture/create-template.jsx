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
import { HclEditor } from "./editor";
import { addTemplate } from "@/actions/templates";
import { Separator } from "@/components/ui/separator";
import { infrastructureVariableTypes } from "@/lib/template-variables";
import { Tag } from "@/components/common/tag";

export function CreateTemplate() {
    const [dialogOpen, setDialogOpen] = useState(false);

    const [name, setName] = useState("");
    const [nameError, setNameError] = useState(false);

    const [code, setCode] = useState("");
    const [codeError, setCodeError] = useState(false);

    const [variables, setVariables] = useState([]);
    const [variablesError, setVariablesError] = useState(false);

    const [platform, setPlatform] = useState("");
    const [platformError, setPlatformError] = useState("");

    const addTemplateHandler = async () => {
        if (!name) return setNameError(true);
        setNameError(false);

        if (!code) return setCodeError(true);
        setCodeError(false);

        if (!platform) return setPlatformError(true);
        setPlatformError(false);

        // TODO: detect if varibale error true

        const result = await addTemplate(
            name,
            code,
            variables,
            "infrastructure",
            platform,
        );
        if (result) {
            setDialogOpen(false);
            setName("");
            setNameError(false);
            setCode("");
            setCodeError(false);
            setVariables([]);
            setVariablesError(false);
            setPlatform("");
            setPlatformError(false);
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
                <Button>Create Template</Button>
            </DialogTrigger>
            <DialogContent className="min-w-[750px]">
                <DialogHeader>
                    <DialogTitle>Create Infrastructure Template</DialogTitle>
                    <DialogDescription>
                        Add your Terraform code below to create a new
                        infrastructure template. Required fields are marked with
                        an asterisk.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                    <div className="flex flex-row gap-4">
                        <div className="grid gap-2 flex-1">
                            <Label htmlFor="name">Name*</Label>
                            <Input
                                id="name"
                                placeholder="Basic Instance"
                                value={name}
                                className={
                                    nameError ? "border border-red-500" : ""
                                }
                                onChange={(e) => setName(e.target.value)}
                            />
                        </div>
                        <div className="grid gap-2">
                            <Label>Platform*</Label>
                            <Select
                                onValueChange={(value) => {
                                    setPlatform(value);
                                }}
                            >
                                <SelectTrigger className="w-[250px]">
                                    <SelectValue placeholder="Platform" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="aws">
                                        <Tag color="amber">aws</Tag>
                                    </SelectItem>
                                    <SelectItem value="digitalocean">
                                        <Tag color="blue">digitalocean</Tag>
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="name">Template*</Label>
                        <HclEditor
                            code={code}
                            setCode={(value) => {
                                setCode(value);
                                extractVariables(value);
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
                                                {infrastructureVariableTypes.map(
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
                            code == "" ||
                            variables.some((v) => !v.type)
                        }
                        onClick={() => addTemplateHandler()}
                    >
                        Create
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
