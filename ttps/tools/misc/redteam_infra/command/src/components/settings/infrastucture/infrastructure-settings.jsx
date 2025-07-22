"use client";

import { updateSetting } from "@/actions/settings";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { useEffect, useState } from "react";

export const InfrastructureSettings = ({ settingsData }) => {
    const [userData, setUserData] = useState(
        settingsData.find((s) => s.name === "userData")?.value || "",
    );
    const [tailscaleTag, setTailscaleTag] = useState(
        settingsData.find((s) => s.name === "tailscaleTag")?.value || "",
    );

    // Autosave after 500ms
    useEffect(() => {
        const timer = setTimeout(() => {
            updateSetting("userData", userData);
        }, 500);

        return () => clearTimeout(timer);
    }, [userData]);

    useEffect(() => {
        const timer = setTimeout(() => {
            updateSetting("tailscaleTag", tailscaleTag);
        }, 500);

        return () => clearTimeout(timer);
    }, [tailscaleTag]);

    return (
        <ScrollArea>
            <div className="grid gap-4">
                <div className="grid gap-2">
                    <Label htmlFor="email">Extra User-Data</Label>
                    <p className="text-sm text-muted-foreground">
                        The default user-data script will install Tailscale.
                        However, you can add extra code here.
                    </p>
                    <Textarea
                        value={userData}
                        onChange={(e) => setUserData(e.target.value)}
                    />
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="email">Tailscale Tag</Label>
                    <p className="text-sm text-muted-foreground">
                        Tailscale tag applied to both Forge Nucleus and default
                        infrastructure. Must be defined within Tailscale ACLs
                    </p>
                    <Input
                        placeholder="lodestar-forge"
                        value={tailscaleTag}
                        onChange={(e) => setTailscaleTag(e.target.value)}
                    />
                </div>
            </div>
        </ScrollArea>
    );
};
