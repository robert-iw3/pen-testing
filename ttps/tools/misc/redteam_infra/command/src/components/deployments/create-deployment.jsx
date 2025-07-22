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
import { awsRegions, digitalOceanRegions } from "@/lib/regions";
import { addDeployment } from "@/actions/deployments";

import { Textarea } from "../ui/textarea";
import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectLabel,
    SelectTrigger,
    SelectValue,
} from "../ui/select";

export function CreateDeployment({ projectId, integrations, sshKeys }) {
    const [dialogOpen, setDialogOpen] = useState(false);

    const [name, setName] = useState("");
    const [nameError, setNameError] = useState(false);

    const [description, setDescription] = useState("");

    const [platform, setPlatform] = useState("");
    const [platformIntegration, setPlatformIntegration] = useState("");
    const [platformIntegrationError, setPlatformIntegrationError] =
        useState(false);

    const [tailscale, setTailscale] = useState("");
    const [tailscaleIntegration, setTailscaleIntegration] = useState("");
    const [tailscaleIntegrationError, setTailscaleIntegrationError] =
        useState(false);

    const [sshKey, setSshKey] = useState("");
    const [sshKeyError, setSshKeyError] = useState(false);

    const [region, setRegion] = useState("");
    const [regionError, setRegionError] = useState("");

    const addDeploymentHandler = async () => {
        if (!name) {
            return setNameError(true);
        } else setNameError(false);

        if (!platformIntegration) {
            return setPlatformIntegrationError(true);
        } else setPlatformIntegrationError(false);

        if (!region) {
            return setRegionError(true);
        } else setRegionError(false);

        if (!tailscaleIntegration) {
            return setTailscaleIntegrationError(true);
        } else setTailscaleIntegrationError(false);

        if (!sshKey) {
            return setSshKey(true);
        } else setSshKeyError(false);

        const result = await addDeployment(
            name,
            description,
            sshKey,
            platformIntegration,
            region,
            tailscaleIntegration,
            projectId,
        );

        if (result) {
            setName("");
            setNameError(false);

            setDescription("");

            setPlatform("");
            setPlatformIntegration("");
            setPlatformIntegrationError(false);

            setTailscale("");
            setTailscaleIntegration("");
            setTailscaleIntegrationError(false);

            setRegion("");
            setRegionError(false);

            setSshKey("");
            setSshKeyError(false);

            setDialogOpen(false);
        }
    };

    return (
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
                <Button>Create Deployment</Button>
            </DialogTrigger>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Create Deployment</DialogTitle>
                    <DialogDescription>
                        Complete the form below to create a new deployment.
                        Required fields are marked with an asterisk.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Label htmlFor="domain">Name*</Label>
                        <Input
                            id="name"
                            placeholder="Primary Deployment"
                            value={name}
                            className={nameError ? "border border-red-500" : ""}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="domain">Description</Label>
                        <Textarea
                            id="description"
                            placeholder="Primary infrastructure for the upcoming red team."
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="type">Platform*</Label>
                        <Select
                            value={platformIntegration}
                            onValueChange={(value) => {
                                setPlatformIntegration(value);
                                setPlatform(
                                    integrations.find(
                                        (integration) =>
                                            integration.id === value,
                                    ).platform,
                                );

                                setRegion("");
                            }}
                        >
                            <SelectTrigger
                                className={
                                    platformIntegrationError
                                        ? "border border-red-500"
                                        : ""
                                }
                            >
                                <SelectValue placeholder="Select a platform" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    <SelectLabel>Platforms</SelectLabel>
                                    {integrations
                                        .filter(
                                            (i) => i.platform !== "tailscale",
                                        )
                                        .map((integration) => (
                                            <SelectItem
                                                key={integration.id}
                                                value={integration.id}
                                            >
                                                {integration.name}
                                            </SelectItem>
                                        ))}
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="type">Region*</Label>
                        <Select value={region} onValueChange={setRegion}>
                            <SelectTrigger
                                className={
                                    regionError ? "border border-red-500" : ""
                                }
                                disabled={!platform}
                            >
                                <SelectValue placeholder="Select a region" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    <SelectLabel>Regions</SelectLabel>
                                    {platform === "aws"
                                        ? awsRegions.map((awsRegion) => (
                                              <SelectItem
                                                  key={awsRegion.code}
                                                  value={awsRegion.code}
                                              >
                                                  {awsRegion.name}
                                              </SelectItem>
                                          ))
                                        : digitalOceanRegions.map(
                                              (digitalOceanRegion) => (
                                                  <SelectItem
                                                      key={
                                                          digitalOceanRegion.code
                                                      }
                                                      value={
                                                          digitalOceanRegion.code
                                                      }
                                                  >
                                                      {digitalOceanRegion.name}
                                                  </SelectItem>
                                              ),
                                          )}
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="type">Tailscale Key*</Label>
                        <Select
                            value={tailscaleIntegration}
                            onValueChange={(value) => {
                                setTailscaleIntegration(value);
                                setTailscale(
                                    integrations.find(
                                        (integration) =>
                                            integration.id === value,
                                    ).platform,
                                );
                            }}
                        >
                            <SelectTrigger
                                className={
                                    tailscaleIntegrationError
                                        ? "border border-red-500"
                                        : ""
                                }
                            >
                                <SelectValue placeholder="Select a platform" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    <SelectLabel>Tailscale Keys</SelectLabel>
                                    {integrations
                                        .filter(
                                            (i) => i.platform === "tailscale",
                                        )
                                        .map((integration) => (
                                            <SelectItem
                                                key={integration.id}
                                                value={integration.id}
                                            >
                                                {integration.name}
                                            </SelectItem>
                                        ))}
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="type">SSH Key*</Label>
                        <Select value={sshKey} onValueChange={setSshKey}>
                            <SelectTrigger
                                className={
                                    sshKeyError ? "border border-red-500" : ""
                                }
                            >
                                <SelectValue placeholder="Select an SSH key" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    <SelectLabel>SSH Keys</SelectLabel>
                                    {sshKeys.map((sshKey) => (
                                        <SelectItem
                                            key={sshKey.id}
                                            value={sshKey.id}
                                        >
                                            {sshKey.name}
                                        </SelectItem>
                                    ))}
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </div>
                </div>
                <DialogFooter>
                    <div className="w-full flex flex-row justify-between items-center">
                        <p className="text-sm text-red-500">
                            {/* {domainError ? "Enter a valid domain." : ""} */}
                        </p>
                        <Button
                            type="button"
                            disabled={
                                name === "" ||
                                sshKey === "" ||
                                tailscaleIntegration === "" ||
                                platformIntegration === "" ||
                                region === ""
                            }
                            onClick={() => addDeploymentHandler()}
                        >
                            Create
                        </Button>
                    </div>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
