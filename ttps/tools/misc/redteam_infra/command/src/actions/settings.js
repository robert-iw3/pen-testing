"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const updateSetting = async (name, value) => {
    try {
        const rows = await apiFetch(`/settings`, "POST", {
            name,
            value,
        });
        return rows ? rows : false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};
