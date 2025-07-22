import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

import { redirect } from "next/navigation";
import { DetailsCard } from "@/components/projects/details-card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { DangerCard } from "@/components/projects/danger-card";
import { InfrastructureCard } from "@/components/projects/infrastructure-card";
import { apiFetch } from "@/lib/utils";

export default async function Dashboard(props) {
    const params = await props.params;
    const projectId = await params.projectId;

    const project = await apiFetch(
        `/projects?projectId=${projectId}&includeInfrastructure=true`,
    );
    const projectDeployments = await apiFetch(
        `/deployments?projectId=${projectId}`,
    );

    const data = Object.entries(
        project[0]?.infrastructure.reduce((acc, obj) => {
            acc[obj.status] = (acc[obj.status] || 0) + 1;
            return acc;
        }, {}),
    ).map(([status, count]) => ({ status, count }));

    if (project.length < 1) redirect("/projects");
    return (
        <div className="p-6 h-full flex flex-col overflow-y-hidden gap-6">
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
                        <BreadcrumbPage>Overview</BreadcrumbPage>
                    </BreadcrumbItem>
                </BreadcrumbList>
            </Breadcrumb>
            <ScrollArea type="scroll">
                <div className="flex gap-6 flex-col">
                    <div className="grid grid-cols-3 gap-6 grid-rows-2">
                        <DetailsCard
                            project={project[0]}
                            className="col-span-2 row-span-2"
                        />
                        <InfrastructureCard
                            className="col-span-1 row-span-2"
                            data={data}
                        />
                    </div>
                    <DangerCard
                        project={project[0]}
                        hasDeployments={projectDeployments.length > 0}
                    />
                </div>
            </ScrollArea>
        </div>
    );
}
