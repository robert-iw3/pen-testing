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
import { addDomain } from "@/actions/domains";

export function CreateDomain({ projectId }) {
    const [dialogOpen, setDialogOpen] = useState(false);
    const [domain, setDomain] = useState("");
    const [domainError, setDomainError] = useState(false);

    const addDomainHandler = async () => {
        if (!domain) return setDomainError(true);
        if (
            !/^(?=.{1,253}\.?$)(?:(?!-|[^.]+_)[A-Za-z0-9-_]{1,63}(?<!-)(?:\.|$)){2,}$/.test(
                domain,
            )
        )
            return setDomainError(true);

        const result = await addDomain(domain, projectId);
        if (result) {
            setDomain("");
            setDomainError(false);
            setDialogOpen(false);
        }
    };

    return (
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
                <Button>Add Domain</Button>
            </DialogTrigger>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Add Domain</DialogTitle>
                    <DialogDescription>
                        Complete the form below to add a new domain. Required
                        fields are marked with an asterisk.
                    </DialogDescription>
                </DialogHeader>
                <div className="">
                    <Label htmlFor="domain">Domain*</Label>
                    <Input
                        id="domain"
                        placeholder="example.com"
                        value={domain}
                        className={domainError ? "border border-red-500" : ""}
                        onChange={(e) => setDomain(e.target.value)}
                    />
                </div>
                <DialogFooter>
                    <div className="w-full flex flex-row justify-between items-center">
                        <p className="text-sm text-red-500">
                            {domainError ? "Enter a valid domain." : ""}
                        </p>
                        <Button
                            type="button"
                            disabled={domain == ""}
                            onClick={() => addDomainHandler()}
                        >
                            Add
                        </Button>
                    </div>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
