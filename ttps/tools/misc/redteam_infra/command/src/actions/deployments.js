"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addDeployment = async (
    name,
    description,
    sshKeyId,
    platformIntegrationId,
    region,
    tailscaleIntegrationId,
    projectId,
) => {
    try {
        const rows = await apiFetch(`/deployments`, "POST", {
            name,
            description,
            sshKeyId,
            platformId: platformIntegrationId,
            region,
            tailscaleId: tailscaleIntegrationId,
            projectId,
        });
        return rows ? rows : false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const deleteDeployment = async (id) => {
    try {
        await apiFetch(`/deployments/${id}`, "DELETE");
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const prepareDeployment = async (id) => {
    try {
        await apiFetch(`/deployments/${id}/prepare`, "POST");
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const deployDeployment = async (id) => {
    try {
        await apiFetch(`/deployments/${id}/deploy`, "POST");
        return true;
    } catch (e) {
        console.log(e);
        return false;
    } finally {
        revalidatePath("/", "layout");
    }
};

export const configureDeployment = async (id) => {
    try {
        await apiFetch(`/deployments/${id}/configure`, "POST");
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};
