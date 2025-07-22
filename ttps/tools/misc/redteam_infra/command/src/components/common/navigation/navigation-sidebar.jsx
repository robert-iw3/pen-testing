import { NavLinks } from "./navigation-links";
import { ProjectSwitcher } from "./navigation-project-switcher";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarRail,
} from "@/components/ui/sidebar";
import { NavUser } from "./navigation-user";

import { auth } from "@/lib/auth";
import { apiFetch } from "@/lib/utils";

export async function AppSidebar({ projectId }) {
  const session = await auth();
  const rows = await apiFetch("/projects");
  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <ProjectSwitcher projects={rows} currentProjectId={projectId} />
      </SidebarHeader>
      <SidebarContent>
        <NavLinks projectId={projectId} />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={session.user} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
