import { columns } from "@/components/domains/columns";
import { CreateDomain } from "@/components/domains/create-domain";
import { DataTable } from "@/components/common/data-table/data-table";

import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbList,
    BreadcrumbLink,
    BreadcrumbSeparator,
    BreadcrumbPage,
} from "@/components/ui/breadcrumb";
import { apiFetch } from "@/lib/utils";

export default async function Domains(props) {
    const params = await props.params;
    const rows = await apiFetch(`/domains?projectId=${params.projectId}`);
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
                        <BreadcrumbPage>Domains</BreadcrumbPage>
                    </BreadcrumbItem>
                </BreadcrumbList>
            </Breadcrumb>
            <Card className="overflow-hidden flex flex-col h-full">
                <CardHeader>
                    <CardTitle className="text-2xl">Domains</CardTitle>
                </CardHeader>
                <CardContent className="flex-1 min-h-0">
                    <DataTable
                        columns={columns}
                        data={rows}
                        search={true}
                        searchColumn={"domain"}
                        searchPlaceholder={"Search domains..."}
                        buttonComponent={
                            <CreateDomain projectId={params.projectId} />
                        }
                        redirectTemplate={`/projects/${params.projectId}/domains/{id}`}
                        showOptions={true}
                        archivable={true}
                    />
                </CardContent>
            </Card>
        </div>
    );
}
