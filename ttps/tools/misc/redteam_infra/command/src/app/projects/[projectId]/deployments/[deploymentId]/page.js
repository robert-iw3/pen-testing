import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

import { redirect } from "next/navigation";
import { DetailsCard } from "@/components/deployments/details-card";
import { StatusCard } from "@/components/deployments/status-card";
import { InfrastructureCard } from "@/components/deployments/infrastructure-card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { apiFetch } from "@/lib/utils";
import { DangerCard } from "@/components/deployments/danger-card";

export default async function Deployment(props) {
    const params = await props.params;
    const deploymentId = params.deploymentId;
    const projectId = await params.projectId;

    let deploymentData = {};

    const allDeployments = await apiFetch(
        `/deployments?projectId=${projectId}`,
    );

    deploymentData = await allDeployments.find(
        (deployment) => deployment.id === deploymentId,
    );
    if (!deploymentData) redirect(`/projects/${projectId}/deployments`);

    var infrastructureRows = await apiFetch(
        `/deployments/${deploymentId}/infrastructure`,
    );

    const domains = await apiFetch(`/domains?projectId=${projectId}`);

    infrastructureRows = await Promise.all(
        infrastructureRows.map(async (row) => {
            const resources = await apiFetch(
                `/deployments/${deploymentId}/infrastructure/${row.id}/resources`,
            );
            return { ...row, resources };
        }),
    );

    const templates = await apiFetch(`/templates`);

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
                        <BreadcrumbLink
                            href={`/projects/${projectId}/deployments`}
                        >
                            Deployments
                        </BreadcrumbLink>
                    </BreadcrumbItem>
                    <BreadcrumbSeparator />
                    <BreadcrumbItem>
                        <BreadcrumbPage>{deploymentData?.name}</BreadcrumbPage>
                    </BreadcrumbItem>
                </BreadcrumbList>
            </Breadcrumb>
            <ScrollArea type="scroll">
                <div className="flex gap-6 flex-col">
                    <div className="grid grid-cols-3 gap-6 grid-rows-2">
                        <DetailsCard
                            deployment={deploymentData}
                            className="col-span-2 row-span-2"
                        />
                        <StatusCard
                            className="row-span-2"
                            deployment={deploymentData}
                            infrastructure={infrastructureRows}
                        />
                    </div>
                    <InfrastructureCard
                        infrastructure={infrastructureRows}
                        templates={templates}
                        status={deploymentData?.status}
                        deploymentId={deploymentId}
                        domains={domains}
                        platform={deploymentData?.platform}
                    />
                    <DangerCard deployment={deploymentData} />
                </div>
            </ScrollArea>
        </div>
    );
}
