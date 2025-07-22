"use client";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";

import { ProjectCard } from "@/components/projects/project-card";
import { CreateProject } from "@/components/projects/create-project";
import { Input } from "../ui/input";
import { ScrollArea } from "../ui/scroll-area";
import { Button } from "../ui/button";
import { useState, useMemo } from "react";

export default function AllProjects({ projects }) {
    const [searchValue, setSearchValue] = useState("");

    const filteredProjects = useMemo(
        () =>
            projects
                .filter((project) =>
                    project.name
                        .toLowerCase()
                        .includes(searchValue.toLowerCase()),
                )
                .sort((a, b) => {
                    if (
                        a.startDate === "1970-01-01" &&
                        b.startDate !== "1970-01-01"
                    )
                        return 1;
                    if (
                        a.startDate !== "1970-01-01" &&
                        b.startDate === "1970-01-01"
                    )
                        return -1;
                    return new Date(a.startDate) - new Date(b.startDate);
                }),
        [projects, searchValue],
    );
    return (
        <Card className="w-1/3">
            <CardHeader className="flex flex-row justify-between">
                <div className="flex flex-col space-y-1.5">
                    <CardTitle>Projects</CardTitle>
                    <CardDescription>
                        Select a project below to continue.
                    </CardDescription>
                </div>
                <CreateProject>
                    <Button>Create</Button>
                </CreateProject>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
                <Input
                    placeholder="Search projects..."
                    value={searchValue}
                    onChange={(e) => setSearchValue(e.target.value)}
                />
                <ScrollArea className="min-h-[calc(100vh-700px)] max-h-[calc(100vh-450px)]">
                    {filteredProjects.length ? (
                        <div className="flex flex-col gap-2">
                            {filteredProjects.map((project) => (
                                <ProjectCard
                                    key={project.id}
                                    project={project}
                                />
                            ))}
                        </div>
                    ) : (
                        <div className="flex rounded-md min-h-[calc(100vh-700px)] max-h-[calc(100vh-450px)] w-full items-center justify-center border border-dashed">
                            <p className="text-sm text-muted-foreground">
                                No projects found.
                            </p>
                        </div>
                    )}
                </ScrollArea>
            </CardContent>
        </Card>
    );
}
