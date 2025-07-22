import { columns } from "@/components/deployments/columns";
import { CreateDeployment } from "@/components/deployments/create-deployment";
import { DataTable } from "@/components/common/data-table/data-table";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbList,
    BreadcrumbLink,
    BreadcrumbSeparator,
    BreadcrumbPage,
} from "@/components/ui/breadcrumb";
import { apiFetch } from "@/lib/utils";

export default async function Deployments(props) {
    const params = await props.params;
    const rows = await apiFetch(`/deployments?projectId=${params.projectId}`);

    const keyRows = await apiFetch("/ssh-keys");
    const integrationRows = await apiFetch("/integrations");

    return (
        <div className="p-6 h-full flex flex-col overflow-y-hidden gap-6">
            <Breadcrumb>
                <BreadcrumbList>
                    <BreadcrumbItem>
                        <BreadcrumbLink
                            href={`/projects/${params.projectId}/overview`}
                        >
                            Project
                        </BreadcrumbLink>
                    </BreadcrumbItem>
                    <BreadcrumbSeparator />
                    <BreadcrumbItem>
                        <BreadcrumbPage>Deployments</BreadcrumbPage>
                    </BreadcrumbItem>
                </BreadcrumbList>
            </Breadcrumb>
            <Card className="overflow-hidden flex flex-col h-full">
                <CardHeader>
                    <CardTitle className="text-2xl">Deployments</CardTitle>
                </CardHeader>
                <CardContent className="flex-1 min-h-0">
                    <DataTable
                        columns={columns}
                        data={rows}
                        search={true}
                        searchColumn={"domain"}
                        searchPlaceholder={"Search deployments..."}
                        buttonComponent={
                            <CreateDeployment
                                projectId={params.projectId}
                                integrations={integrationRows}
                                sshKeys={keyRows}
                            />
                        }
                        redirectTemplate={`/projects/${params.projectId}/deployments/{id}`}
                        showOptions={true}
                        archivable={false}
                    />
                </CardContent>
            </Card>
        </div>
    );
}
