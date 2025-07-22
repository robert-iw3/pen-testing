import { Separator } from "@/components/ui/separator";
import { DataTable } from "@/components/common/data-table/data-table";
import { columns } from "@/components/settings/files/columns";
import { CreateFile } from "@/components/settings/files/create-file";
import { apiFetch } from "@/lib/utils";

export default async function InfrastructureTemplates() {
    var rows = await apiFetch("/files");

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium">File Manager</h3>
                <p className="text-sm text-muted-foreground">
                    Modify and create templates which can be utilised by
                    Ansible.
                </p>
            </div>
            <Separator />
            <DataTable
                columns={columns}
                data={rows}
                search={true}
                searchPlaceholder={"Search files..."}
                buttonComponent={<CreateFile />}
                searchColumn={"name"}
            />
        </div>
    );
}
