"use server";

import { revalidatePath } from "next/cache";
import { apiFetch } from "@/lib/utils";

export const addIntegration = async (name, platform, keyId, secretKey) => {
    try {
        const integration = await apiFetch("/integrations", "POST", {
            name,
            platform,
            keyId,
            secretKey,
        });
        return (await integration) ?? false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};

export const deleteIntegration = async (id) => {
    try {
        if (await apiFetch(`/integrations/${id}`, "DELETE")) return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};
