import { AppSidebar } from "@/components/common/navigation/navigation-sidebar";
import { SidebarProvider } from "@/components/ui/sidebar";
import { apiFetch } from "@/lib/utils";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";

export default async function RootLayout(props) {
    const params = await props.params;
    const cookieStore = await cookies();
    const defaultOpen = cookieStore.get("sidebar_state")?.value === "true";

    const { children } = props;

    const projectId = await params.projectId;
    const rows = await apiFetch("/projects");
    if (rows.length < 1 || !rows.find((row) => row.id === projectId))
        redirect("/projects");

    return (
        <SidebarProvider defaultOpen={defaultOpen}>
            <AppSidebar projectId={projectId} />
            <main className="bg-muted/40 flex-1 overflow-hidden">
                <div className="h-full overflow-auto">{children}</div>
            </main>
        </SidebarProvider>
    );
}
