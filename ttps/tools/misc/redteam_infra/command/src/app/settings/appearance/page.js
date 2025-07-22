import { Separator } from "@/components/ui/separator";

export default function Appearance() {
    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium">Appearance</h3>
                <p className="text-sm text-muted-foreground">
                    Update the appearance settings for Forge.
                </p>
            </div>
            <Separator />
        </div>
    );
}
