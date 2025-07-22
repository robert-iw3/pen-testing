import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";
import { DetailsCard } from "@/components/domains/details-card";
import { HealthCard } from "@/components/domains/health-card";
import { DNSCard } from "@/components/domains/dns-card";
import { InfrastuctureCard } from "@/components/domains/infrastucture-card";

import { ScrollArea } from "@/components/ui/scroll-area";
import { DangerCard } from "@/components/domains/danger-card";
import { apiFetch } from "@/lib/utils";

export default async function Domain(props) {
    const params = await props.params;
    const domainId = params.domainId;
    const projectId = await params.projectId;

    let domainsData,
        dnsRecordsData = [];

    const allDomains = await apiFetch(`/domains?projectId=${projectId}`);

    domainsData = await allDomains.find((domain) => domain.id === domainId);
    if (!domainsData) redirect(`/projects/${projectId}/domains`);

    // If domain is archived, redirect
    if (domainsData.state === "archived")
        redirect(`/projects/${projectId}/domains`);

    dnsRecordsData = await apiFetch(`/domains/${domainId}/dns`);
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
                        <BreadcrumbLink href={`/projects/${projectId}/domains`}>
                            Domains
                        </BreadcrumbLink>
                    </BreadcrumbItem>
                    <BreadcrumbSeparator />
                    <BreadcrumbItem>
                        <BreadcrumbPage>{domainsData?.domain}</BreadcrumbPage>
                    </BreadcrumbItem>
                </BreadcrumbList>
            </Breadcrumb>
            <ScrollArea type="scroll">
                <div className="grid grid-cols-3 gap-6 grid-rows-4">
                    <DetailsCard
                        domain={domainsData}
                        className="col-span-2 row-span-2"
                    />
                    <HealthCard domain={domainsData} />
                    <InfrastuctureCard
                        domain={domainsData}
                        className="col-span-1 row-span-2"
                    />
                    <DNSCard
                        domain={domainsData}
                        dnsRecords={dnsRecordsData}
                        className="col-span-2 row-span-2"
                    />
                    <DangerCard domain={domainsData} />
                </div>
            </ScrollArea>
        </div>
    );
}
