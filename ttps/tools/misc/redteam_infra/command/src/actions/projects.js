"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addProject = async (name, startDate, endDate) => {
    try {
        const rows = await apiFetch(`/projects`, "POST", {
            name,
            startDate: startDate ? startDate : null,
            endDate: endDate ? endDate : null,
        });
        if (rows.length > 0) return rows[0];
        return false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const updateProject = async (id, name, startDate, endDate, status) => {
    if (name === "" || status === "") return false;
    try {
        const updatedProject = await apiFetch(`/projects/${id}`, "PUT", {
            name,
            startDate,
            endDate,
            status,
        });
    } catch (e) {
        console.log(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const deleteProject = async (id) => {
    if (!id) return false;
    try {
        await apiFetch(`/projects/${id}`, "DELETE");
    } catch (e) {
        console.log(e);
    } finally {
        revalidatePath("/", "layout");
    }
};
