"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addKey = async (name) => {
    try {
        const key = await apiFetch("/ssh-keys", "POST", { name });
        return (await key[0].private) ?? false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};

export const deleteKey = async (id) => {
    try {
        if (await apiFetch(`/ssh-keys/${id}`, "DELETE")) return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};
