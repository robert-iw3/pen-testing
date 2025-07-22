"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addDomain = async (domain, projectId) => {
    try {
        const rows = await apiFetch(`/domains`, "POST", {
            domain,
            projectId,
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

export const changeHealthSettings = async (id, autoScan, state) => {
    if (autoScan) state = "pending-analysis";
    try {
        await apiFetch(`/domains/${id}`, "PUT", {
            stateAutoScan: autoScan,
            state,
            updated: new Date(),
            stateUpdated: new Date(),
        });

        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const quickUpdateAutoScan = async (id, value) => {
    try {
        await apiFetch(`/domains/${id}`, "PUT", {
            stateAutoScan: value,
            updated: new Date(),
        });
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const updateDnsAutoScan = async (id, value) => {
    try {
        await apiFetch(`/domains/${id}`, "PUT", {
            dnsAutoScan: value,
            updated: new Date(),
        });
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const archiveDomain = async (id, projectId) => {
    try {
        await apiFetch(`/domains/${id}`, "PUT", {
            archived: true,
            updated: new Date(),
            stateUpdated: new Date(),
        });
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const unarchiveDomain = async (id, projectId) => {
    try {
        await apiFetch(`/domains/${id}`, "PUT", {
            archived: false,
            updated: new Date(),
            stateUpdated: new Date(),
        });
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const deleteDomain = async (domainId, projectId) => {
    try {
        await apiFetch(`/domains/${domainId}`, "DELETE");
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};
