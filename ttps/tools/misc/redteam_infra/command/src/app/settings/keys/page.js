import { Separator } from "@/components/ui/separator";
import { DataTable } from "@/components/common/data-table/data-table";
import { columns } from "@/components/settings/keys/columns";
import { CreateKey } from "@/components/settings/keys/create-key";
import { apiFetch } from "@/lib/utils";

export default async function Keys() {
    const rows = await apiFetch("/ssh-keys");

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium">SSH Keys</h3>
                <p className="text-sm text-muted-foreground">
                    Modify and create SSH keys used by Forge when managing
                    infrastructure.
                </p>
            </div>
            <Separator />
            <DataTable
                columns={columns}
                data={rows}
                search={true}
                searchPlaceholder={"Search keys..."}
                // redirectTemplate={"/settings/users/{id}"}
                buttonComponent={<CreateKey />}
                searchColumn={"name"}
            />
        </div>
    );
}
