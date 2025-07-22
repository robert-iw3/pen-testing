import { Separator } from "@/components/ui/separator";
import { columns } from "@/components/settings/integrations/columns";
import { CreateIntegration } from "@/components/settings/integrations/create-integration";
import { DataTable } from "@/components/common/data-table/data-table";
import { apiFetch } from "@/lib/utils";

export default async function Integrations() {
    const rows = await apiFetch("/integrations");

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium">Integrations</h3>
                <p className="text-sm text-muted-foreground">
                    Add and modify third-party integrations used by Forge.
                </p>
            </div>
            <Separator />
            <DataTable
                columns={columns}
                data={rows}
                search={true}
                searchPlaceholder={"Search integrations..."}
                searchColumn={"name"}
                // redirectTemplate={"/settings/users/{id}"}
                buttonComponent={<CreateIntegration />}
            />
        </div>
    );
}
