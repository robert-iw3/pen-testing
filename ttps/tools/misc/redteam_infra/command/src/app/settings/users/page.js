import { Separator } from "@/components/ui/separator";
import { DataTable } from "@/components/common/data-table/data-table";
import { columns } from "@/components/settings/users/columns";
import { CreateUser } from "@/components/settings/users/create-user";
import { apiFetch } from "@/lib/utils";

export default async function Settings() {
    const rows = await apiFetch("/users");

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium">Users</h3>
                <p className="text-sm text-muted-foreground">
                    Create and modify Forge&apos;s users.
                </p>
            </div>
            <Separator />
            <DataTable
                columns={columns}
                data={rows}
                search={true}
                searchPlaceholder={"Search users..."}
                redirectTemplate={"/settings/users/{id}"}
                buttonComponent={<CreateUser />}
                searchColumn={"name"}
            />
        </div>
    );
}
