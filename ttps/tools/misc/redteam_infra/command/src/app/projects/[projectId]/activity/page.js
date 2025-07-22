import { LogsTable } from "@/components/logs/logs-table/logs-table";
import { columns } from "@/components/logs/logs-table/columns";
import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { apiFetch } from "@/lib/utils";

export default async function ActivityLog(props) {
    const params = await props.params;
    const projectId = await params.projectId;

    const rows = await apiFetch(`/logs?projectId=${projectId}`);

    return (
        <div className="p-6 h-screen w-full flex flex-col overflow-y-hidden gap-6">
            <Breadcrumb>
                <BreadcrumbList>
                    <BreadcrumbItem>
                        <BreadcrumbLink
                            href={`/projects/${projectId}/overview`}
                        >
                            Project
                        </BreadcrumbLink>
                    </BreadcrumbItem>
                    <BreadcrumbSeparator />
                    <BreadcrumbItem>
                        <BreadcrumbPage>Activity Log</BreadcrumbPage>
                    </BreadcrumbItem>
                </BreadcrumbList>
            </Breadcrumb>
            <Card className="overflow-hidden flex flex-col h-full w-full relative">
                <CardHeader>
                    <CardTitle className="text-2xl">Activity Log</CardTitle>
                </CardHeader>
                <CardContent className="flex-1 min-h-0 overflow-hidden max-w-full">
                    <LogsTable
                        columns={columns}
                        data={rows}
                        search={true}
                        searchColumn={"message"}
                        searchPlaceholder={"Search logs..."}
                    />
                </CardContent>
            </Card>
        </div>
    );
}
