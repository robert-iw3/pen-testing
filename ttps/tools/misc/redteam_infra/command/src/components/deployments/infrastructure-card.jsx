"use client";

import { cn } from "@/lib/utils";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardDescription,
} from "../ui/card";
import { Button } from "../ui/button";
import { useState } from "react";
import { DataTable } from "../common/data-table/data-table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "../ui/label";
import { Input } from "../ui/input";
import { Textarea } from "../ui/textarea";
import { columns } from "./infrastructure-columns";
import { addInfrastructure } from "@/actions/infrastructure";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import { useParams } from "next/navigation";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";
import { CheckIcon, ChevronsUpDownIcon } from "lucide-react";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "../ui/command";

export function InfrastructureCard({
  className,
  infrastructure,
  templates,
  status,
  deploymentId,
  domains,
  platform,
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [showVariables, setShowVariables] = useState(false);
  const [name, setName] = useState("");
  const [nameError, setNameError] = useState(false);

  const [infrastructureTemplate, setInfrastructureTemplate] = useState("");
  const [infrastructureTemplateOpen, setInfrastructureTemplateOpen] =
    useState(false);
  const [infrastructureTemplateError, setInfrastructureTemplateError] =
    useState(false);

  const [variables, setVariables] = useState([]);

  const [description, setDescription] = useState("");

  const infrastructureTemplates = templates.filter(
    (template) =>
      template.type === "infrastructure" && template.platform === platform,
  );

  const configurationTemplates = templates.filter(
    (template) => template.type === "configuration",
  );

  const resources = infrastructure.map((item) => item.resources).flat();

  const hosts = resources.filter(
    (resource) =>
      resource.resourceType === "aws_instance" ||
      resource.resourceType === "digitalocean_droplet",
  );
  const subnets = resources.filter(
    (resource) => resource.resourceType === "aws_subnet",
  );
  const vpcs = resources.filter(
    (resource) =>
      resource.resourceType === "aws_vpc" ||
      resource.resourceType === "digitalocean_vpc",
  );

  const params = useParams();

  const handleSubmit = async () => {
    if (!name) {
      return setNameError(true);
    } else {
      setNameError(false);
    }
    if (!infrastructureTemplate) {
      return setInfrastructureTemplateError(true);
    } else {
      setInfrastructureTemplateError(false);
    }

    addInfrastructure(
      deploymentId,
      name,
      infrastructureTemplate,
      description,
      variables,
    );

    setName("");
    setInfrastructureTemplate("");
    setDescription("");
    setShowVariables(false);
    setVariables([]);

    return setIsOpen(false);
  };

  return (
    <Card className={cn(className)}>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Infrastructure</CardTitle>
          <CardDescription
            className="text-xs text-muted-foreground mt-1.5"
            suppressHydrationWarning
          >
            Infrastructure associated with this deployment. To add configuration
            templates, select the infrastructure below.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2" style={{ marginTop: 0 }}>
          <Dialog
            open={isOpen}
            onOpenChange={(v) => {
              if (status !== "ready-to-prepare" && status !== "preparing")
                setIsOpen(v);
            }}
          >
            <DialogTrigger asChild>
              <div className="flex items-center" style={{ marginTop: 0 }}>
                <Button
                  size="sm"
                  disabled={
                    status === "ready-to-prepare" || status === "preparing"
                  }
                >
                  Add
                </Button>
              </div>
            </DialogTrigger>
            {showVariables ? (
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Template Variables</DialogTitle>
                  <DialogDescription>
                    Complete the form below to add template variables. Required
                    fields are marked with an asterisk.
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                  {variables.map(
                    (variable, index) =>
                      variable.type !== "infrastructure-id" && (
                        <div className="grid gap-2" key={variable.name}>
                          <Label htmlFor={variable.name}>
                            {variable.name}*
                          </Label>
                          {(() => {
                            switch (variable?.type) {
                              case "text":
                                return (
                                  <Input
                                    id={variable.name}
                                    placeholder="Example"
                                    value={variable.value}
                                    onChange={(e) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value =
                                        e.target.value;

                                      setVariables(updatedVariables);
                                    }}
                                  />
                                );
                              case "number":
                                return (
                                  <Input
                                    id={variable.name}
                                    placeholder="0"
                                    type="number"
                                    value={variable.value}
                                    onChange={(e) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value =
                                        e.target.value;

                                      setVariables(updatedVariables);
                                    }}
                                  />
                                );
                              case "domain":
                                return (
                                  <Select
                                    value={variable.value}
                                    onValueChange={(value) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value = value;

                                      setVariables(updatedVariables);
                                    }}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select a domain" />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectGroup>
                                        <SelectLabel>Domains</SelectLabel>
                                        {domains.map((domain) => (
                                          <SelectItem
                                            key={domain.id}
                                            value={domain.domain}
                                          >
                                            {domain.domain}
                                          </SelectItem>
                                        ))}
                                      </SelectGroup>
                                    </SelectContent>
                                  </Select>
                                );
                              case "private-ip":
                                return (
                                  <Select
                                    value={variable.value}
                                    onValueChange={(value) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value = value;

                                      setVariables(updatedVariables);
                                    }}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select a host" />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectGroup>
                                        <SelectLabel>Hosts</SelectLabel>
                                        {hosts.map((host) => (
                                          <SelectItem
                                            key={host.id}
                                            value={host.privateIp}
                                          >
                                            {host.resourceName}
                                          </SelectItem>
                                        ))}
                                      </SelectGroup>
                                    </SelectContent>
                                  </Select>
                                );
                              case "public-ip":
                                return (
                                  <Select
                                    value={variable.value}
                                    onValueChange={(value) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value = value;

                                      setVariables(updatedVariables);
                                    }}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select a host" />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectGroup>
                                        <SelectLabel>Hosts</SelectLabel>
                                        {hosts.map((host) => (
                                          <SelectItem
                                            key={host.id}
                                            value={host.publicIp}
                                          >
                                            {host.resourceName}
                                          </SelectItem>
                                        ))}
                                      </SelectGroup>
                                    </SelectContent>
                                  </Select>
                                );
                              case "tailscale-ip":
                                return (
                                  <Select
                                    value={variable.value}
                                    onValueChange={(value) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value = value;

                                      setVariables(updatedVariables);
                                    }}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select a host" />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectGroup>
                                        <SelectLabel>Hosts</SelectLabel>
                                        {hosts.map((host) => (
                                          <SelectItem
                                            key={host.id}
                                            value={host.tailscaleIp}
                                          >
                                            {host.resourceName}
                                          </SelectItem>
                                        ))}
                                      </SelectGroup>
                                    </SelectContent>
                                  </Select>
                                );
                              case "host-terraform":
                                return (
                                  <Select
                                    value={variable.value}
                                    onValueChange={(value) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value = value;

                                      setVariables(updatedVariables);
                                    }}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select a host" />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectGroup>
                                        <SelectLabel>Hosts</SelectLabel>
                                        {hosts.map((host) => (
                                          <SelectItem
                                            key={host.id}
                                            value={`${host.resourceType}.${host.resourceName}`}
                                          >
                                            {host.resourceName}
                                          </SelectItem>
                                        ))}
                                      </SelectGroup>
                                    </SelectContent>
                                  </Select>
                                );
                              case "subnet":
                                return (
                                  <Select
                                    value={variable.value}
                                    onValueChange={(value) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value = value;

                                      setVariables(updatedVariables);
                                    }}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select a subnet" />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectGroup>
                                        <SelectLabel>Subnets</SelectLabel>
                                        {subnets.map((subnet) => (
                                          <SelectItem
                                            key={subnet.id}
                                            value={`${subnet.resourceType}.${subnet.resourceName}.id`}
                                          >
                                            {subnet.resourceName}
                                          </SelectItem>
                                        ))}
                                      </SelectGroup>
                                    </SelectContent>
                                  </Select>
                                );
                              case "vpc":
                                return (
                                  <Select
                                    value={variable.value}
                                    onValueChange={(value) => {
                                      const updatedVariables = [...variables];

                                      updatedVariables[index].value = value;

                                      setVariables(updatedVariables);
                                    }}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select a VPC" />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectGroup>
                                        <SelectLabel>VPCs</SelectLabel>
                                        {vpcs.map((vpc) => (
                                          <SelectItem
                                            key={vpc.id}
                                            value={`${vpc.resourceType}.${vpc.resourceName}.id`}
                                          >
                                            {vpc.resourceName}
                                          </SelectItem>
                                        ))}
                                      </SelectGroup>
                                    </SelectContent>
                                  </Select>
                                );
                            }
                          })()}
                        </div>
                      ),
                  )}
                </div>
                <DialogFooter>
                  <Button
                    disabled={
                      !variables.every((v) => {
                        if (v.type !== "infrastructure-id")
                          return v.value && v.value !== "";
                        return true;
                      })
                    }
                    onClick={() => {
                      handleSubmit();
                    }}
                  >
                    Add
                  </Button>
                </DialogFooter>
              </DialogContent>
            ) : (
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add Infrastructure</DialogTitle>
                  <DialogDescription>
                    Complete the form below to add infrastructure to this
                    deployment. Required fields are marked with an asterisk.
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                  <div className="grid gap-2">
                    <Label htmlFor="domain">Name*</Label>
                    <Input
                      id="name"
                      placeholder="C2 Redirector"
                      value={name}
                      className={nameError ? "border border-red-500" : ""}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="type">Infrastructure Template*</Label>
                    <Popover
                      open={infrastructureTemplateOpen}
                      onOpenChange={setInfrastructureTemplateOpen}
                    >
                      <PopoverTrigger asChild>
                        <Button
                          variant="outline"
                          role="combobox"
                          aria-expanded={open}
                          className={`w-full justify-between font-normal ${infrastructureTemplate ? "" : "text-muted-foreground"}`}
                        >
                          {infrastructureTemplate
                            ? templates.find(
                                (t) => t.id === infrastructureTemplate,
                              ).name
                            : "Select Template"}
                          <ChevronsUpDownIcon className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0">
                        <Command
                          filter={(value, search, keywords) => {
                            return keywords
                              .join(" ")
                              .toLowerCase()
                              .includes(search.toLowerCase())
                              ? 1
                              : 0;
                          }}
                        >
                          <CommandInput placeholder="Search templates..." />
                          <CommandList>
                            <CommandEmpty>No template found.</CommandEmpty>
                            <CommandGroup>
                              {infrastructureTemplates.map((template) => (
                                <CommandItem
                                  key={template.id}
                                  value={template.id}
                                  keywords={[template.name]}
                                  onSelect={(value) => {
                                    const templateVariables = templates.find(
                                      (t) => t.id === value,
                                    ).variables;

                                    setVariables([...templateVariables]);
                                    setInfrastructureTemplate(value);
                                    setInfrastructureTemplateOpen(false);
                                  }}
                                >
                                  <CheckIcon
                                    className={cn(
                                      "mr-2 h-4 w-4",
                                      infrastructureTemplate === template.id
                                        ? "opacity-100"
                                        : "opacity-0",
                                    )}
                                  />
                                  {template.name}
                                </CommandItem>
                              ))}
                            </CommandGroup>
                          </CommandList>
                        </Command>
                      </PopoverContent>
                    </Popover>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="domain">Description</Label>
                    <Textarea
                      id="description"
                      placeholder="Basic redirector for the short C2 server."
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                    />
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    disabled={name === "" || infrastructureTemplate === ""}
                    onClick={() => {
                      setShowVariables(true);
                    }}
                  >
                    Next
                  </Button>
                </DialogFooter>
              </DialogContent>
            )}
          </Dialog>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-[400px]">
          <DataTable
            columns={columns(configurationTemplates)}
            data={infrastructure}
            redirectTemplate={`/projects/${params.projectId}/deployments/${params.deploymentId}/infrastructure/{id}`}
          />
        </div>
      </CardContent>
    </Card>
  );
}
