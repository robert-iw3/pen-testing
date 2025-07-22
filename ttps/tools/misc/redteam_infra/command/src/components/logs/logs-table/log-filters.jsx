import { Check, PlusCircle } from "lucide-react";

import { cn } from "@/lib/utils";

import { Tag } from "@/components/common/tag";
import { Button } from "@/components/ui/button";
import {
    Command,
    CommandEmpty,
    CommandGroup,
    CommandInput,
    CommandItem,
    CommandList,
    CommandSeparator,
} from "@/components/ui/command";
import {
    Popover,
    PopoverContent,
    PopoverTrigger,
} from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";

const statuses = [
    {
        value: "info",
        label: <Tag>info</Tag>,
    },
    {
        value: "warning",
        label: <Tag color={"amber"}>warning</Tag>,
    },
    {
        value: "error",
        label: <Tag color={"red"}>error</Tag>,
    },
    {
        value: "unknown",
        label: <Tag>unknown</Tag>,
    },
];

const sources = [
    {
        value: "tailscale",
        label: <Tag>Tailscale</Tag>,
    },
    {
        value: "terraform",
        label: <Tag>Terraform</Tag>,
    },
    {
        value: "connection",
        label: <Tag>Connection</Tag>,
    },
    {
        value: "nucleus",
        label: <Tag>Nucleus</Tag>,
    },
    {
        value: "radar",
        label: <Tag>Radar</Tag>,
    },
];

export function LogTableFacetedFilters({ table }) {
    const sourceColumn = table.getColumn("source");
    const statusColumn = table.getColumn("status");

    return (
        <div className="flex flex-row gap-2">
            <LogTableFacetedFilter
                column={sourceColumn}
                title={"Source"}
                options={sources}
            />
            <LogTableFacetedFilter
                column={statusColumn}
                title={"Status"}
                options={statuses}
            />
        </div>
    );
}

export function LogTableFacetedFilter({ column, options, title }) {
    const facets = column?.getFacetedUniqueValues();
    const selectedValues = new Set(column?.getFilterValue());

    return (
        <Popover>
            <PopoverTrigger asChild>
                <Button variant="outline" className="border-dashed">
                    <PlusCircle />
                    {title}
                    {selectedValues?.size > 0 && (
                        <>
                            <Separator
                                orientation="vertical"
                                className="mx-2 h-4"
                            />
                            <Tag
                                variant="secondary"
                                className="rounded-sm px-1 font-normal lg:hidden"
                            >
                                {selectedValues.size}
                            </Tag>
                            <div className="hidden space-x-1 lg:flex">
                                {selectedValues.size > 2 ? (
                                    <Tag
                                        variant="secondary"
                                        className="rounded-sm px-1 font-normal"
                                    >
                                        {selectedValues.size} selected
                                    </Tag>
                                ) : (
                                    options
                                        .filter((option) =>
                                            selectedValues.has(option.value),
                                        )
                                        .map((option) => option.label)
                                )}
                            </div>
                        </>
                    )}
                </Button>
            </PopoverTrigger>
            <PopoverContent className="w-[200px] p-0" align="start">
                <Command>
                    <CommandInput placeholder={title} />
                    <CommandList>
                        <CommandEmpty>No results found.</CommandEmpty>
                        <CommandGroup>
                            {options.map((option) => {
                                const isSelected = selectedValues.has(
                                    option.value,
                                );
                                return (
                                    <CommandItem
                                        key={option.value}
                                        onSelect={() => {
                                            if (isSelected) {
                                                selectedValues.delete(
                                                    option.value,
                                                );
                                            } else {
                                                selectedValues.add(
                                                    option.value,
                                                );
                                            }
                                            const filterValues =
                                                Array.from(selectedValues);
                                            column?.setFilterValue(
                                                filterValues.length
                                                    ? filterValues
                                                    : undefined,
                                            );
                                        }}
                                    >
                                        <div
                                            className={cn(
                                                "mr-2 flex h-4 w-4 items-center justify-center rounded-sm border border-primary",
                                                isSelected
                                                    ? "bg-primary text-primary-foreground"
                                                    : "opacity-50 [&_svg]:invisible",
                                            )}
                                        >
                                            <Check />
                                        </div>

                                        <span>{option.label}</span>
                                        {facets?.get(option.value) && (
                                            <span className="ml-auto flex h-4 w-4 items-center justify-center font-mono text-xs">
                                                {facets.get(option.value)}
                                            </span>
                                        )}
                                    </CommandItem>
                                );
                            })}
                        </CommandGroup>
                        {selectedValues.size > 0 && (
                            <>
                                <CommandSeparator />
                                <CommandGroup>
                                    <CommandItem
                                        onSelect={() =>
                                            column?.setFilterValue(undefined)
                                        }
                                        className="justify-center text-center"
                                    >
                                        Clear filters
                                    </CommandItem>
                                </CommandGroup>
                            </>
                        )}
                    </CommandList>
                </Command>
            </PopoverContent>
        </Popover>
    );
}
