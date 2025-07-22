import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

import { redirect } from "next/navigation";
import { DetailsCard } from "@/components/infrastructure/details-card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { apiFetch } from "@/lib/utils";
import { DangerCard } from "@/components/deployments/danger-card";
import { NetworkCard } from "@/components/infrastructure/network-card";
import { ResourcesCard } from "@/components/infrastructure/resources-card";
import { ConfigurationCard } from "@/components/infrastructure/configuration-card";

export default async function Infrastructure(props) {
    const params = await props.params;
    const deploymentId = params.deploymentId;
    const infrastructureId = params.infrastructureId;
    const projectId = await params.projectId;

    let deploymentData = {};

    const allDeployments = await apiFetch(
        `/deployments?projectId=${projectId}`,
    );

    deploymentData = await allDeployments.find(
        (deployment) => deployment.id === deploymentId,
    );

    if (!deploymentData) redirect(`/projects/${projectId}/deployments`);

    var allInfrastructure = await apiFetch(
        `/deployments/${deploymentId}/infrastructure`,
    );

    const domains = await apiFetch(`/domains?projectId=${projectId}`);

    allInfrastructure = await Promise.all(
        allInfrastructure.map(async (row) => {
            const resources = await apiFetch(
                `/deployments/${deploymentId}/infrastructure/${row.id}/resources`,
            );
            return { ...row, resources };
        }),
    );

    const infrastructureData = await allInfrastructure.find(
        (infrastructure) => infrastructure.id === infrastructureId,
    );

    const templates = await apiFetch(`/templates`);
    const files = await apiFetch(`/files`);

    const resources = allInfrastructure.map((item) => item.resources).flat();

    const hosts = resources.filter(
        (resource) =>
            resource.resourceType === "aws_instance" ||
            resource.resourceType === "digitalocean_droplet",
    );
    const subnets = resources.filter(
        (resource) => resource.resourceType === "aws_subnet",
    );
    const vpcs = resources.filter(
        (resource) => resource.resourceType === "aws_vpc",
    );

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
                        <BreadcrumbLink
                            href={`/projects/${projectId}/deployments/${deploymentId}`}
                        >
                            {deploymentData?.name}
                        </BreadcrumbLink>
                    </BreadcrumbItem>
                    <BreadcrumbSeparator />
                    <BreadcrumbItem>
                        <BreadcrumbPage>
                            {infrastructureData?.name}
                        </BreadcrumbPage>
                    </BreadcrumbItem>
                </BreadcrumbList>
            </Breadcrumb>
            <ScrollArea type="scroll">
                <div className="flex gap-6 flex-col">
                    <div className="grid grid-cols-3 gap-6 grid-rows-2">
                        <DetailsCard
                            infrastructure={infrastructureData}
                            templates={templates}
                            className="col-span-2 row-span-1"
                        />
                        <NetworkCard
                            infrastructure={infrastructureData}
                            className="col-span-1 row-span-1"
                        />
                        {infrastructureData.status !== "default" ? (
                            <ConfigurationCard
                                infrastructureId={infrastructureId}
                                deploymentId={deploymentId}
                                infrastructure={infrastructureData}
                                className="col-span-3 row-span-2"
                                templates={templates}
                                domains={domains}
                                files={files}
                                hosts={hosts}
                            />
                        ) : null}

                        <ResourcesCard
                            infrastructure={infrastructureData}
                            className="col-span-3 row-span-2"
                        />
                    </div>
                </div>
            </ScrollArea>
        </div>
    );
}
