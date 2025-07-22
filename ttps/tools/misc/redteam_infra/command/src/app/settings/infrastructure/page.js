import { InfrastructureSettings } from "@/components/settings/infrastucture/infrastructure-settings";
import { Separator } from "@/components/ui/separator";
import { apiFetch } from "@/lib/utils";

export default async function Infrastructure() {
    const settingsData = await apiFetch("/settings");

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium">Infrastructure</h3>
                <p className="text-sm text-muted-foreground">
                    Update the infrastructure settings for Forge.
                </p>
            </div>
            <Separator />
            <InfrastructureSettings settingsData={settingsData} />
        </div>
    );
}
