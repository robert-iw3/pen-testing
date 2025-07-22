"use client";

import { apiFetch, cn } from "@/lib/utils";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardDescription,
} from "../ui/card";
import { Button } from "../ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import { Label } from "../ui/label";
import { useState, useMemo } from "react";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  DragOverlay,
  MeasuringStrategy,
} from "@dnd-kit/core";
import {
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
  arrayMove,
} from "@dnd-kit/sortable";
import { SortableConfiguration } from "./sortable-configuration";
import { CheckIcon, ChevronsUpDownIcon, PlusCircle } from "lucide-react";
import { ScrollArea } from "../ui/scroll-area";
import { Input } from "../ui/input";
import { v4 } from "uuid";
import { addInfrastructureConfigurations } from "@/actions/infrastructure";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "../ui/command";

export function ConfigurationCard({
  className,
  infrastructure,
  infrastructureId,
  templates,
  domains,
  files,
  hosts,
  deploymentId,
}) {
  const [activeId, setActiveId] = useState(null);
  const [items, setItems] = useState(infrastructure?.configurations || []);

  const [editing, setEditing] = useState(false);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState("");
  const [templateSelectOpen, setTemplateSelectOpen] = useState(false);

  const [variables, setVariables] = useState([]);
  const [showTemplateVariables, setShowTemplateVariables] = useState(false);
  const [showFileVariables, setShowFileVariables] = useState(false);

  const itemIds = useMemo(() => items.map((item) => item.id), [items]);
  const configurationTemplates = templates.filter(
    (template) => template.type === "configuration",
  );

  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    }),
  );

  const updateFileVariable = (fileVariableId, variableName, variableValue) => {
    let tempVariables = [...variables];

    tempVariables = tempVariables.map((variable) => {
      if (variable.id === fileVariableId) {
        return {
          ...variable,
          variables: variable.variables.map((v) => {
            if (v.name === variableName) {
              return { ...v, value: variableValue };
            } else return v;
          }),
        };
      } else return variable;
    });

    setVariables([...tempVariables]);
  };

  const TemplateVariablesNextButton = () => {
    if (
      templates.find((t) => t.id === selectedTemplate)?.variables.length > 0
    ) {
      return (
        <Button
          disabled={selectedTemplate == ""}
          onClick={() => {
            setVariables([
              ...templates
                .find((t) => t.id === selectedTemplate)
                ?.variables.map((v) => ({ ...v, id: v4() })),
            ]);
            setShowTemplateVariables(true);
          }}
        >
          Next
        </Button>
      );
    } else {
      return (
        <Button
          disabled={selectedTemplate == ""}
          onClick={() => {
            setItems([
              ...items,
              {
                id: v4(),
                template: selectedTemplate,
                name: templates.find((t) => t.id === selectedTemplate)?.name,
                variables,
              },
            ]);
            setShowFileVariables(false);
            setShowTemplateVariables(false);
            setDialogOpen(false);
            setSelectedTemplate("");
          }}
        >
          Add
        </Button>
      );
    }
  };

  const FileVariablesNextButton = () => {
    const selectedFiles = variables.filter((v) => v.type === "file");
    let selectedFilesHaveVariables = false;
    selectedFiles.forEach((selectedFile) => {
      const file = files.find((f) => f.id === selectedFile.value);
      if (file?.variables.length > 0) {
        selectedFilesHaveVariables = true;
      }
    });

    if (selectedFilesHaveVariables) {
      return (
        <Button
          disabled={selectedTemplate == ""}
          onClick={() => {
            const newVariables = variables.map((variable) => {
              if (variable.type === "file") {
                const fileVariables =
                  files.find((f) => f.id === variable.value)?.variables || [];

                return {
                  ...variable,
                  variables: fileVariables,
                };
              }

              return variable;
            });
            setVariables([...newVariables]);
            setShowTemplateVariables(false);
            setShowFileVariables(true);
          }}
        >
          Next
        </Button>
      );
    } else {
      return (
        <Button
          // TODO: disabled if vars empty
          onClick={() => {
            setItems([
              ...items,
              {
                id: v4(),
                template: selectedTemplate,
                name: templates.find((t) => t.id === selectedTemplate)?.name,
                variables,
              },
            ]);
            setShowFileVariables(false);
            setShowTemplateVariables(false);
            setDialogOpen(false);
            setSelectedTemplate("");
          }}
        >
          Add
        </Button>
      );
    }
  };

  return (
    <Card className={cn("flex flex-col", className)}>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Configuration</CardTitle>
          <CardDescription className="text-xs text-muted-foreground mt-1.5">
            Add and modify configuration templates for your infrastructure.
          </CardDescription>
        </div>
        <div className="flex items-center pr-4" style={{ marginTop: 0 }}>
          {editing ? (
            <div className="flex flex-row gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setEditing(false);
                  setItems([...(infrastructure?.configurations || [])]);
                }}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  addInfrastructureConfigurations(
                    deploymentId,
                    infrastructureId,
                    items,
                  );
                  setEditing(false);
                }}
              >
                Save
              </Button>
            </div>
          ) : (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditing(true)}
            >
              Edit
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="h-full">
        {editing || items.length > 0 ? (
          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragStart={handleDragStart}
            onDragEnd={handleDragEnd}
            measuring={{
              droppable: { strategy: MeasuringStrategy.Always },
            }}
          >
            <SortableContext
              items={itemIds}
              strategy={verticalListSortingStrategy}
            >
              <ScrollArea className="h-[300px]">
                <div className="pr-4 flex flex-col gap-2">
                  {items.map((item) => (
                    <SortableConfiguration
                      key={item.id}
                      id={item.id}
                      display={item.name}
                      disabled={!editing}
                      className={item.id === activeId ? "opacity-25" : ""}
                      onRemoveHandler={removeItem}
                    />
                  ))}
                  <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                    {editing && (
                      <DialogTrigger asChild>
                        <div className="p-5 border border-gray-300 rounded-lg border-dashed hover:bg-secondary cursor-pointer h-[78px]">
                          <div className="flex flex-row items-center justify-center h-full w-full text-sm text-muted-foreground gap-0.5">
                            <PlusCircle className="h-4" /> Add configuration
                            template
                          </div>
                        </div>
                      </DialogTrigger>
                    )}

                    {showTemplateVariables ? (
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Template Variables</DialogTitle>
                          <DialogDescription>
                            Complete the form below to add template variables.
                            Required fields are marked with an asterisk.
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
                                              const updatedVariables = [
                                                ...variables,
                                              ];

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
                                              const updatedVariables = [
                                                ...variables,
                                              ];

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
                                              const updatedVariables = [
                                                ...variables,
                                              ];

                                              updatedVariables[index].value =
                                                value;

                                              setVariables(updatedVariables);
                                            }}
                                          >
                                            <SelectTrigger>
                                              <SelectValue placeholder="Select a domain" />
                                            </SelectTrigger>
                                            <SelectContent>
                                              <SelectGroup>
                                                <SelectLabel>
                                                  Domains
                                                </SelectLabel>
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
                                              const updatedVariables = [
                                                ...variables,
                                              ];

                                              updatedVariables[index].value =
                                                value;

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
                                              const updatedVariables = [
                                                ...variables,
                                              ];

                                              updatedVariables[index].value =
                                                value;

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
                                              const updatedVariables = [
                                                ...variables,
                                              ];

                                              updatedVariables[index].value =
                                                value;

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
                                      case "file":
                                        return (
                                          <Select
                                            value={variable.value}
                                            onValueChange={(value) => {
                                              const updatedVariables = [
                                                ...variables,
                                              ];

                                              updatedVariables[index].value =
                                                value;

                                              setVariables(updatedVariables);
                                            }}
                                          >
                                            <SelectTrigger>
                                              <SelectValue placeholder="Select a file" />
                                            </SelectTrigger>
                                            <SelectContent>
                                              <SelectGroup>
                                                <SelectLabel>Files</SelectLabel>
                                                {files.map((file) => (
                                                  <SelectItem
                                                    key={file.id}
                                                    value={file.id}
                                                  >
                                                    {`${file.name}.${file.extension}`}
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
                          <FileVariablesNextButton />
                        </DialogFooter>
                      </DialogContent>
                    ) : showFileVariables ? (
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>File Variables</DialogTitle>
                          <DialogDescription>
                            Complete the form below to add template variables.
                            Required fields are marked with an asterisk.
                          </DialogDescription>
                        </DialogHeader>
                        <div className="grid gap-4">
                          {variables
                            .filter(
                              (variable) =>
                                variable.type === "file" &&
                                variable.variables.length > 0,
                            )
                            .map((file) => {
                              return (
                                <div className="grid gap-4" key={file.value}>
                                  <p>{`${
                                    files.find((f) => f.id === file.value).name
                                  }.${
                                    files.find((f) => f.id === file.value)
                                      .extension
                                  }`}</p>
                                  {file.variables.map(
                                    (variable, index) =>
                                      variable.type !== "infrastructure-id" && (
                                        <div
                                          className="grid gap-2"
                                          key={variable.name}
                                        >
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
                                                      updateFileVariable(
                                                        file.id,
                                                        variable.name,
                                                        e.target.value,
                                                      );
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
                                                      updateFileVariable(
                                                        file.id,
                                                        variable.name,
                                                        e.target.value,
                                                      );
                                                    }}
                                                  />
                                                );
                                              case "domain":
                                                return (
                                                  <Select
                                                    value={variable.value}
                                                    onValueChange={(value) => {
                                                      updateFileVariable(
                                                        file.id,
                                                        variable.name,
                                                        value,
                                                      );
                                                    }}
                                                  >
                                                    <SelectTrigger>
                                                      <SelectValue placeholder="Select a domain" />
                                                    </SelectTrigger>
                                                    <SelectContent>
                                                      <SelectGroup>
                                                        <SelectLabel>
                                                          Domains
                                                        </SelectLabel>
                                                        {domains.map(
                                                          (domain) => (
                                                            <SelectItem
                                                              key={domain.id}
                                                              value={
                                                                domain.domain
                                                              }
                                                            >
                                                              {domain.domain}
                                                            </SelectItem>
                                                          ),
                                                        )}
                                                      </SelectGroup>
                                                    </SelectContent>
                                                  </Select>
                                                );
                                              case "private-ip":
                                                return (
                                                  <Select
                                                    value={variable.value}
                                                    onValueChange={(value) => {
                                                      updateFileVariable(
                                                        file.id,
                                                        variable.name,
                                                        value,
                                                      );
                                                    }}
                                                  >
                                                    <SelectTrigger>
                                                      <SelectValue placeholder="Select a host" />
                                                    </SelectTrigger>
                                                    <SelectContent>
                                                      <SelectGroup>
                                                        <SelectLabel>
                                                          Hosts
                                                        </SelectLabel>
                                                        {hosts.map((host) => (
                                                          <SelectItem
                                                            key={host.id}
                                                            value={
                                                              host.privateIp
                                                            }
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
                                                      updateFileVariable(
                                                        file.id,
                                                        variable.name,
                                                        value,
                                                      );
                                                    }}
                                                  >
                                                    <SelectTrigger>
                                                      <SelectValue placeholder="Select a host" />
                                                    </SelectTrigger>
                                                    <SelectContent>
                                                      <SelectGroup>
                                                        <SelectLabel>
                                                          Hosts
                                                        </SelectLabel>
                                                        {hosts.map((host) => (
                                                          <SelectItem
                                                            key={host.id}
                                                            value={
                                                              host.publicIp
                                                            }
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
                                                      updateFileVariable(
                                                        file.id,
                                                        variable.name,
                                                        value,
                                                      );
                                                    }}
                                                  >
                                                    <SelectTrigger>
                                                      <SelectValue placeholder="Select a host" />
                                                    </SelectTrigger>
                                                    <SelectContent>
                                                      <SelectGroup>
                                                        <SelectLabel>
                                                          Hosts
                                                        </SelectLabel>
                                                        {hosts.map((host) => (
                                                          <SelectItem
                                                            key={host.id}
                                                            value={
                                                              host.tailscaleIp
                                                            }
                                                          >
                                                            {host.resourceName}
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
                              );
                            })}
                        </div>
                        <DialogFooter>
                          <div className="w-full flex flex-row justify-between items-center">
                            <Button
                              onClick={() => {
                                setShowFileVariables(false);
                                setShowTemplateVariables(false);
                                setDialogOpen(false);
                                setSelectedTemplate("");
                                setItems([
                                  ...items,
                                  {
                                    id: v4(),
                                    template: selectedTemplate,
                                    name: templates.find(
                                      (t) => t.id === selectedTemplate,
                                    )?.name,
                                    variables,
                                  },
                                ]);
                              }}
                            >
                              Add
                            </Button>
                          </div>
                        </DialogFooter>
                      </DialogContent>
                    ) : (
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Add Configuration</DialogTitle>
                          <DialogDescription>
                            Complete the form below to add a new configuration.
                            Required fields are marked with an asterisk.
                          </DialogDescription>
                        </DialogHeader>
                        <div className="grid gap-2">
                          <Label htmlFor="template">Template*</Label>
                          <Popover
                            open={templateSelectOpen}
                            onOpenChange={setTemplateSelectOpen}
                          >
                            <PopoverTrigger asChild>
                              <Button
                                variant="outline"
                                role="combobox"
                                aria-expanded={open}
                                className={`w-full justify-between font-normal ${selectedTemplate ? "" : "text-muted-foreground"}`}
                              >
                                {selectedTemplate
                                  ? configurationTemplates.find(
                                      (t) => t.id === selectedTemplate,
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
                                  <CommandEmpty>
                                    No template found.
                                  </CommandEmpty>
                                  <CommandGroup>
                                    {configurationTemplates.map((template) => (
                                      <CommandItem
                                        key={template.id}
                                        value={template.id}
                                        keywords={[template.name]}
                                        onSelect={(value) => {
                                          const templateVariables =
                                            configurationTemplates.find(
                                              (t) => t.id === value,
                                            ).variables;

                                          setVariables([...templateVariables]);
                                          setSelectedTemplate(value);
                                          setTemplateSelectOpen(false);
                                        }}
                                      >
                                        <CheckIcon
                                          className={cn(
                                            "mr-2 h-4 w-4",
                                            selectedTemplate === template.id
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
                        <DialogFooter>
                          <div className="w-full flex flex-row justify-between items-center">
                            <TemplateVariablesNextButton />
                          </div>
                        </DialogFooter>
                      </DialogContent>
                    )}
                  </Dialog>
                </div>
              </ScrollArea>
            </SortableContext>
            <DragOverlay>
              {activeId ? (
                <SortableConfiguration
                  id={activeId}
                  display={items.find((item) => item.id === activeId).name}
                />
              ) : null}
            </DragOverlay>
          </DndContext>
        ) : (
          <div className="flex w-full h-full text-sm text-muted-foreground items-center justify-center border border-dashed rounded-lg">
            No configurations applied.
          </div>
        )}
      </CardContent>
    </Card>
  );

  function handleDragStart(event) {
    const { active } = event;
    setActiveId(active.id);
  }

  function handleDragEnd(event) {
    const { active, over } = event;

    setActiveId(null);

    if (active.id !== over.id) {
      setItems((items) => {
        const oldIndex = items.findIndex((item) => item.id === active.id);
        const newIndex = items.findIndex((item) => item.id === over.id);

        return arrayMove(items, oldIndex, newIndex);
      });
    }
  }

  function removeItem(id) {
    setItems((items) => items.filter((item) => item.id !== id));
  }
}
