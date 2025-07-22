"use client";

import { useState, useEffect, useCallback } from "react";
import { ChevronsUpDown, Plus } from "lucide-react";
import { useRouter, usePathname } from "next/navigation";

import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuShortcut,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    useSidebar,
} from "@/components/ui/sidebar";
import Avvvatars from "avvvatars-react";
import { CreateProject } from "@/components/projects/create-project";

export function ProjectSwitcher({ projects }) {
    const router = useRouter();
    const path = usePathname();

    const { isMobile } = useSidebar();
    const [activeProject, setActiveProject] = useState(
        projects.find((project) => project.id === path.split("/")[2]),
    );

    const handleProjectChange = useCallback(
        (value) => {
            setActiveProject(value);
            router.push(
                path.replace(
                    /\/projects\/[0-9a-fA-F-]+\/(.*)/,
                    `/projects/${value.id}/$1`,
                ),
            );
        },
        [path, router],
    );

    useEffect(() => {
        document.addEventListener("keydown", (e) => {
            if (e.ctrlKey && !isNaN(e.key) && e.key !== " ") {
                handleProjectChange(projects[e.key]);
            }
        });
    }, [handleProjectChange, projects]);

    return (
        <SidebarMenu>
            <SidebarMenuItem>
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <SidebarMenuButton
                            size="lg"
                            className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
                        >
                            <div className="flex aspect-square size-8 items-center justify-center rounded-lg dark:opacity-75">
                                <Avvvatars
                                    radius={8}
                                    value={activeProject.id}
                                    style="shape"
                                    className="px-2"
                                />
                            </div>
                            <div className="grid flex-1 text-left text-sm leading-tight">
                                <span className="truncate font-semibold">
                                    {activeProject.name}
                                </span>
                            </div>
                            <ChevronsUpDown className="ml-auto" />
                        </SidebarMenuButton>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent
                        className="w-[--radix-dropdown-menu-trigger-width] min-w-56 rounded-lg"
                        align="start"
                        side={isMobile ? "bottom" : "right"}
                        sideOffset={4}
                    >
                        <DropdownMenuLabel className="text-xs text-muted-foreground">
                            Projects
                        </DropdownMenuLabel>
                        {projects.map((project, index) => (
                            <DropdownMenuItem
                                key={project.name}
                                onClick={() => handleProjectChange(project)}
                                className="gap-2 p-2"
                            >
                                <div className="flex size-6 items-center justify-center rounded-sm dark:opacity-75">
                                    <Avvvatars
                                        radius={6}
                                        size="24"
                                        value={project.id}
                                        style="shape"
                                    />
                                </div>
                                {project.name}
                                <DropdownMenuShortcut>
                                    Ctl+{index}
                                </DropdownMenuShortcut>
                            </DropdownMenuItem>
                        ))}
                        <DropdownMenuSeparator />
                        <CreateProject>
                            <DropdownMenuItem
                                onSelect={(e) => e.preventDefault()}
                                className="gap-2 p-2"
                            >
                                <div className="flex size-6 items-center justify-center rounded-md border bg-background">
                                    <Plus className="size-4" />
                                </div>
                                <div className="font-medium text-muted-foreground">
                                    Add project
                                </div>
                            </DropdownMenuItem>
                        </CreateProject>
                    </DropdownMenuContent>
                </DropdownMenu>
            </SidebarMenuItem>
        </SidebarMenu>
    );
}
