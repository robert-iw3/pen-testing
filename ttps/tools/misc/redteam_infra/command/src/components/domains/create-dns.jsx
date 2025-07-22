"use client";

import { Button } from "../ui/button";
import { useState } from "react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
    DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "../ui/label";
import { Input } from "../ui/input";
import { createDnsRecord } from "@/actions/dns";
import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectLabel,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";

export function CreateDNS({ domainId }) {
    const [dialogOpen, setDialogOpen] = useState(false);

    const [type, setType] = useState("");
    const [typeError, setTypeError] = useState(false);

    const [name, setName] = useState("");
    const [nameError, setNameError] = useState(false);

    const [value, setValue] = useState("");
    const [valueError, setValueError] = useState(false);

    const addDnsRecordHandler = async () => {
        if (!type) return setTypeError(true);
        if (!name) return setNameError(true);
        if (!value) return setValueError(true);

        const result = await createDnsRecord(type, name, value, domainId);
        if (result) {
            setType("");
            setTypeError(false);

            setName("");
            setNameError(false);

            setValue("");
            setValueError(false);

            setDialogOpen(false);
        }
    };

    return (
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
                <Button size="sm">Add</Button>
            </DialogTrigger>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Add DNS Record</DialogTitle>
                    <DialogDescription>
                        Complete the form below to create a new DNS record.
                        Required fields are marked with an asterisk.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Label htmlFor="type">Type*</Label>
                        <Select value={type} onValueChange={setType}>
                            <SelectTrigger>
                                <SelectValue
                                    placeholder="Select a record type"
                                    className={
                                        typeError ? "border border-red-500" : ""
                                    }
                                />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    <SelectLabel>Record Type</SelectLabel>
                                    <SelectItem value="a">A</SelectItem>
                                    <SelectItem value="aaaa">AAAA</SelectItem>
                                    <SelectItem value="cname">CNAME</SelectItem>
                                    <SelectItem value="mx">MX</SelectItem>
                                    <SelectItem value="ns">NS</SelectItem>
                                    <SelectItem value="ptr">PTR</SelectItem>
                                    <SelectItem value="soa">SOA</SelectItem>
                                    <SelectItem value="srv">SRV</SelectItem>
                                    <SelectItem value="txt">TXT</SelectItem>
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="name">Name*</Label>
                        <Input
                            id="name"
                            placeholder="example.com"
                            value={name}
                            className={nameError ? "border border-red-500" : ""}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="domain">Value*</Label>
                        <Input
                            id="name"
                            placeholder="www.example.com"
                            value={value}
                            className={
                                valueError ? "border border-red-500" : ""
                            }
                            onChange={(e) => setValue(e.target.value)}
                        />
                    </div>
                </div>
                <DialogFooter>
                    <div className="w-full flex flex-row justify-between items-center">
                        <p className="text-sm text-red-500">
                            {typeError
                                ? "Select a record type."
                                : nameError
                                  ? "Enter a record name."
                                  : valueError
                                    ? "Enter a record value."
                                    : ""}
                        </p>
                        <Button
                            type="button"
                            disabled={
                                value === "" || name === "" || type === ""
                            }
                            onClick={() => addDnsRecordHandler()}
                        >
                            Add
                        </Button>
                    </div>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
