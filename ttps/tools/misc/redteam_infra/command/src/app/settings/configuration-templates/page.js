import { Separator } from "@/components/ui/separator";
import { DataTable } from "@/components/common/data-table/data-table";
import { columns } from "@/components/settings/configuration/columns";
import { CreateTemplate } from "@/components/settings/configuration/create-template";
import { apiFetch } from "@/lib/utils";

export default async function InfrastructureTemplates() {
    var rows = await apiFetch("/templates");
    rows = rows.filter((row) => row.type === "configuration");

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium">Configuration Templates</h3>
                <p className="text-sm text-muted-foreground">
                    Modify and create templates used by Ansible when configuring
                    infrastructure.
                </p>
            </div>
            <Separator />
            <DataTable
                columns={columns}
                data={rows}
                search={true}
                searchPlaceholder={"Search templates..."}
                buttonComponent={<CreateTemplate />}
                searchColumn={"name"}
            />
        </div>
    );
}
