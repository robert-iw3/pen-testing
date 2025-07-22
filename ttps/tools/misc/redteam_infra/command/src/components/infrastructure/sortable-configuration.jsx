"use client";

import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { Card } from "../ui/card";
import { Button } from "../ui/button";
import { GripVertical, X } from "lucide-react";
import { cn } from "@/lib/utils";

export const SortableConfiguration = ({ onRemoveHandler, ...props }) => {
    const { attributes, listeners, setNodeRef, transform, transition } =
        useSortable({ id: props.id, disabled: props.disabled });

    const style = {
        transform: CSS.Transform.toString(transform),
        transition,
    };

    return (
        <Card
            ref={setNodeRef}
            style={style}
            className={cn(
                "p-5",
                props.className,
                props.disabled ? "opacity-50" : "",
            )}
        >
            <div className="flex flex-row justify-between w-full">
                <div className="flex flex-row gap-2 items-center">
                    <Button
                        {...attributes}
                        {...listeners}
                        variant="ghost"
                        size="sm"
                        disabled={props.disabled}
                    >
                        <GripVertical className="text-muted-foreground" />
                    </Button>
                    <p>{props.display}</p>
                </div>
                <Button
                    onClick={() => {
                        onRemoveHandler(props.id);
                    }}
                    variant="ghost"
                    size="sm"
                    disabled={props.disabled}
                >
                    <X className={cn("text-muted-foreground")} />
                </Button>
            </div>
        </Card>
    );
};
