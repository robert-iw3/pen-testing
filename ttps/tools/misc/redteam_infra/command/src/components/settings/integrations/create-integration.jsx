"use client";

import { Button } from "@/components/ui/button";
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
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectLabel,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Tag } from "@/components/common/tag";

import { addIntegration } from "@/actions/integrations";

export function CreateIntegration() {
    const [dialogOpen, setDialogOpen] = useState(false);

    const [name, setName] = useState("");
    const [nameError, setNameError] = useState(false);

    const [integration, setIntegration] = useState("");
    const [integrationError, setIntegrationError] = useState(false);

    const [keyId, setKeyId] = useState("");
    const [keyIdError, setKeyIdError] = useState(false);

    const [secretKey, setSecretKey] = useState("");
    const [secretKeyError, setSecretKeyError] = useState(false);

    const addIntegrationHandler = async () => {
        if (!name) return setNameError(true);
        if (!integration) return setIntegrationError(true);

        if (integration === "aws" && !keyId) return setKeyIdError(true);
        if (!secretKey) return setSecretKeyError(true);

        const result = await addIntegration(
            name,
            integration,
            keyId,
            secretKey,
        );
        if (result) {
            setName("");
            setIntegration("");
            setKeyId("");
            setSecretKey("");
            setNameError(false);
            setIntegrationError(false);
            setKeyIdError(false);
            setSecretKeyError(false);
            setDialogOpen(false);
        }
    };

    return (
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
                <Button>Add Integration</Button>
            </DialogTrigger>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Add Integration</DialogTitle>
                    <DialogDescription>
                        Complete the form below to add a new integration.
                        Required fields are marked with an asterisk.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Label htmlFor="name">Name*</Label>
                        <Input
                            id="name"
                            placeholder="AWS Global Access"
                            value={name}
                            className={nameError ? "border border-red-500" : ""}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="integration">Integration*</Label>
                        {integration === "tailscale" && (
                            <p className="text-amber-500 text-xs">
                                Tailscale API keys expire every 90 days. Be sure
                                to keep this value up to date.
                            </p>
                        )}
                        <Select
                            value={integration}
                            onValueChange={setIntegration}
                        >
                            <SelectTrigger>
                                <SelectValue placeholder="Select a integration" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    <SelectLabel>Integrations</SelectLabel>
                                    <SelectItem value="aws">
                                        <Tag color="amber">aws</Tag>
                                    </SelectItem>
                                    <SelectItem value="tailscale">
                                        <Tag color="teal">tailscale</Tag>
                                    </SelectItem>
                                    <SelectItem value="digitalocean">
                                        <Tag color="blue">digitalocean</Tag>
                                    </SelectItem>
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </div>
                    {integration === "aws" && (
                        <div className="grid gap-2">
                            <Label htmlFor="keyId">Key ID*</Label>
                            <Input
                                id="keyId"
                                placeholder="AKIAIOSFODNN7EXAMPLE"
                                value={keyId}
                                className={
                                    keyIdError ? "border border-red-500" : ""
                                }
                                onChange={(e) => setKeyId(e.target.value)}
                            />
                        </div>
                    )}
                    <div className="grid gap-2">
                        <Label htmlFor="secretKey">Secret Key*</Label>
                        <Input
                            id="secretKey"
                            placeholder="••••••••••••"
                            value={secretKey}
                            type="password"
                            className={
                                secretKeyError ? "border border-red-500" : ""
                            }
                            onChange={(e) => setSecretKey(e.target.value)}
                        />
                    </div>
                </div>
                <DialogFooter>
                    <Button
                        type="button"
                        disabled={
                            name == "" ||
                            integration == "" ||
                            secretKey == "" ||
                            (integration === "aws" && keyId == "")
                        }
                        onClick={() => addIntegrationHandler()}
                    >
                        Add
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
