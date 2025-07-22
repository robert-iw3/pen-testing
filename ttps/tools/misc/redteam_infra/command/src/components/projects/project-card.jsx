"use client";

import Avvvatars from "avvvatars-react";
import { useRouter } from "next/navigation";
import { Tag } from "../common/tag";

export function ProjectCard({ project }) {
    const router = useRouter();

    var stateTag;

    switch (project.status) {
        case "not-started":
            stateTag = <Tag color={"gray"}>{project.status}</Tag>;
            break;
        case "done":
            stateTag = <Tag color={"green"}>{project.status}</Tag>;
            break;
        case "in-progress":
            stateTag = <Tag color={"blue"}>{project.status}</Tag>;
            break;
        case "delayed":
            stateTag = <Tag color={"red"}>{project.status}</Tag>;
            break;
        default:
            stateTag = <Tag color={"gray"}>{project.status}</Tag>;
            break;
    }

    return (
        <div
            onClick={() => router.push(`/projects/${project.id}/overview`)}
            key={project.id}
            className="border rounded-md px-3 py-3 h-[60px] flex flex-row hover:bg-accent cursor-pointer justify-between items-center"
        >
            <div className="flex flex-row gap-2">
                <div className="dark:opacity-75">
                    <Avvvatars radius={8} value={project.id} style="shape" />
                </div>
                <div>
                    <p className="text-sm font-medium">{project.name}</p>

                    {project?.startDate == "1970-01-01" &&
                    project?.endDate == "1970-01-01" ? (
                        <p className="text-muted-foreground text-xs">
                            No scheduled dates
                        </p>
                    ) : (
                        <p className="text-muted-foreground text-xs">
                            {project.startDate == "1970-01-01"
                                ? "Unknown"
                                : new Date(project.startDate)
                                      .toISOString()
                                      .split("T")[0]}{" "}
                            -{" "}
                            {project.endDate == "1970-01-01"
                                ? "Unknown"
                                : new Date(project.endDate)
                                      .toISOString()
                                      .split("T")[0]}
                        </p>
                    )}
                </div>
            </div>
            <div>{stateTag}</div>
        </div>
    );
}
