"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addTemplate = async (name, value, variables, type, platform) => {
    try {
        const template = await apiFetch("/templates", "POST", {
            name,
            value,
            variables,
            type,
            platform,
        });

        return template;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};

export const updateTemplate = async (id, name, value, variables) => {
    try {
        const template = await apiFetch(`/templates/${id}`, "PUT", {
            name,
            value,
            variables,
        });

        return template;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};

export const deleteTemplate = async (id) => {
    try {
        await apiFetch(`/templates/${id}`, "DELETE");
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};
