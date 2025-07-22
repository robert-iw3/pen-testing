"use client";

import { cn } from "@/lib/utils";
import {
    Card,
    CardHeader,
    CardTitle,
    CardContent,
    CardDescription,
} from "../ui/card";
import { Label } from "../ui/label";
import { Input } from "../ui/input";
import { useState } from "react";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "../ui/select";
import { Tag } from "../common/tag";
import { Calendar } from "@/components/ui/calendar";
import { Button } from "../ui/button";
import { format } from "date-fns";
import {
    Popover,
    PopoverContent,
    PopoverTrigger,
} from "@/components/ui/popover";
import { Calendar as CalendarIcon } from "lucide-react";
import { updateProject } from "@/actions/projects";

export function DetailsCard({ className, project }) {
    const [isEditing, setIsEditing] = useState(false);
    const [updated, setUpdated] = useState(false);
    const [changesMade, setChangesMade] = useState(false);
    const [name, setName] = useState(project.name);
    const [nameError, setNameError] = useState(false);
    const [status, setStatus] = useState(project.status);
    const [startDate, setStartDate] = useState(project.startDate);
    const [endDate, setEndDate] = useState(project.endDate);
    const handleSubmit = () => {
        if (name === "") return setNameError(true);
        updateProject(project.id, name, startDate, endDate, status);
        setIsEditing(false);
        setChangesMade(false);
        setNameError(false);
    };

    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>Project Details</CardTitle>
                    <CardDescription className="text-xs text-muted-foreground mt-1.5">
                        View and modify the details of this project.
                    </CardDescription>
                </div>
                <div className="flex items-center" style={{ marginTop: 0 }}>
                    {!isEditing ? (
                        <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => setIsEditing(true)}
                        >
                            Edit
                        </Button>
                    ) : (
                        <div className="flex gap-2">
                            <Button
                                size="sm"
                                variant="secondary"
                                onClick={() => setIsEditing(false)}
                            >
                                Cancel
                            </Button>
                            <Button
                                size="sm"
                                onClick={() => handleSubmit()}
                                disabled={!changesMade}
                            >
                                Save
                            </Button>
                        </div>
                    )}
                </div>
            </CardHeader>
            <CardContent>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Label>Name</Label>
                        <Input
                            className={nameError ? "border-red-500" : ""}
                            value={name}
                            onChange={(event) => {
                                setName(event.target.value);
                                setChangesMade(true);
                            }}
                            placeholder="Example Deployment"
                            disabled={!isEditing}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label>Status</Label>
                        <Select
                            defaultValue={status}
                            onValueChange={(value) => {
                                setChangesMade(true);
                                setStatus(value);
                            }}
                            disabled={!isEditing}
                        >
                            <SelectTrigger>
                                <SelectValue placeholder="Select status" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="not-started">
                                    <Tag>Not Started</Tag>
                                </SelectItem>
                                <SelectItem value="in-progress">
                                    <Tag color="blue">In Progress</Tag>
                                </SelectItem>
                                <SelectItem value="done">
                                    <Tag color="green">Done</Tag>
                                </SelectItem>
                                <SelectItem value="delayed">
                                    <Tag color="red">Delayed</Tag>
                                </SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="flex gap-4 flex-row">
                        <div className="grid gap-2 flex-1">
                            <Label htmlFor="startDate">Start Date</Label>
                            <Popover>
                                <PopoverTrigger asChild>
                                    <Button
                                        variant={"outline"}
                                        className={cn(
                                            "justify-start text-left",
                                            !startDate &&
                                                "text-muted-foreground",
                                        )}
                                        disabled={!isEditing}
                                    >
                                        <CalendarIcon className=" h-4 w-4" />
                                        {startDate ? (
                                            format(startDate, "PPP")
                                        ) : (
                                            <span>Start Date</span>
                                        )}
                                    </Button>
                                </PopoverTrigger>
                                {/* TODO: Fix issues with date not showing correctly in calander... */}
                                <PopoverContent
                                    className="w-auto p-0"
                                    align="start"
                                >
                                    <Calendar
                                        mode="single"
                                        selected={startDate}
                                        onSelect={(value) => {
                                            setUpdated(true);
                                            setStartDate(value);
                                        }}
                                    />
                                </PopoverContent>
                            </Popover>
                        </div>
                        <div className="grid gap-2 flex-1">
                            <Label htmlFor="endDate">End Date</Label>
                            <Popover>
                                <PopoverTrigger asChild>
                                    <Button
                                        variant={"outline"}
                                        className={cn(
                                            "justify-start text-left",
                                            !endDate && "text-muted-foreground",
                                        )}
                                        disabled={!isEditing}
                                    >
                                        <CalendarIcon className=" h-4 w-4" />
                                        {endDate ? (
                                            format(endDate, "PPP")
                                        ) : (
                                            <span>End Date</span>
                                        )}
                                    </Button>
                                </PopoverTrigger>
                                <PopoverContent
                                    className="w-auto p-0"
                                    align="start"
                                >
                                    <Calendar
                                        mode="single"
                                        selected={endDate}
                                        onSelect={(value) => {
                                            setUpdated(true);
                                            setEndDate(value);
                                        }}
                                        fromDate={startDate}
                                    />
                                </PopoverContent>
                            </Popover>
                        </div>
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
