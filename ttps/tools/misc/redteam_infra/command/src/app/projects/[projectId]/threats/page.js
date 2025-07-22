import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

import { auth } from "@/lib/auth";

import { ScrollArea } from "@/components/ui/scroll-area";

export default async function ThreatGroups(props) {
  const params = await props.params;
  const projectId = await params.projectId;
  return (
    <div className="p-6 h-full flex flex-col overflow-y-hidden gap-6">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href={`/projects/${projectId}/overview`}>
              Project
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>Threat Intelligence</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <ScrollArea type="scroll">
        <div className="grid grid-cols-3 gap-6 grid-rows-4"></div>
      </ScrollArea>
    </div>
  );
}
