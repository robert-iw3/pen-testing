import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";
import { SidebarProvider } from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { SettingsSidebar } from "@/components/common/navigation/settings-sidebar";
export default async function RootLayout({ children }) {
    const session = await auth();

    if (!session) redirect("/auth/signin");

    return (
        <div className="space-y-6 p-10 h-screen flex flex-col">
            <div className="space-y-0.5">
                <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
                <p className="text-muted-foreground">
                    Manage Forge&apos;s settings and templates.
                </p>
            </div>
            <Separator className="my-6" />
            <div className="overflow-x-hidden flex-1 flex">
                <SidebarProvider className="items-start min-h-0">
                    <SettingsSidebar />
                    <main className="flex flex-1 flex-col overflow-x-hidden">
                        <div className="h-full overflow-auto pl-4">
                            {children}
                        </div>
                    </main>
                </SidebarProvider>
            </div>
        </div>
    );
}
