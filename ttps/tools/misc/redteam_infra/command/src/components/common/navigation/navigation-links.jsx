"use client";

import { Bug, House, Link2, List, Shapes } from "lucide-react";

import {
    SidebarGroup,
    SidebarGroupLabel,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarSeparator,
} from "@/components/ui/sidebar";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function NavLinks({ projectId }) {
    const links = [
        {
            title: "Overview",
            url: `/projects/${projectId}/overview`,
            icon: House,
        },
        {
            title: "Activity Log",
            url: `/projects/${projectId}/activity`,
            icon: List,
        },
        {
            title: "Deployments",
            url: `/projects/${projectId}/deployments`,
            icon: Shapes,
        },
        {
            title: "Domains",
            url: `/projects/${projectId}/domains`,
            icon: Link2,
        },
        // { separator: true },
        // {
        //   title: "Threat Intelligence",
        //   url: `/projects/${projectId}/threats`,
        //   icon: Bug,
        // },
    ];

    const path = usePathname();

    return (
        <SidebarGroup>
            <SidebarGroupLabel>Project</SidebarGroupLabel>
            <SidebarMenu>
                {links.map((link) => {
                    return link.separator ? (
                        <SidebarSeparator />
                    ) : (
                        <SidebarMenuItem key={link.title}>
                            <SidebarMenuButton
                                tooltip={link.title}
                                asChild
                                isActive={path.startsWith(link.url)}
                            >
                                <Link href={link.url}>
                                    {link.icon && <link.icon />}
                                    <span>{link.title}</span>
                                </Link>
                            </SidebarMenuButton>
                        </SidebarMenuItem>
                    );
                })}
            </SidebarMenu>
        </SidebarGroup>
    );
}
