"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addInfrastructure = async (
    deploymentId,
    name,
    infrastructureTemplateId,
    description,
    variables,
) => {
    try {
        const rows = await apiFetch(
            `/deployments/${deploymentId}/infrastructure`,
            "POST",
            {
                name,
                infrastructureTemplateId,
                description,
                variables,
            },
        );
        if (rows.length > 0) return rows[0];
        return false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const updateInfrastructure = async (
    deploymentId,
    infrastructureId,
    name,
    description,
    configurations,
) => {
    try {
        const rows = await apiFetch(
            `/deployments/${deploymentId}/infrastructure/${infrastructureId}`,
            "PUT",
            {
                name,
                description,
                configurations,
            },
        );
        if (rows.length > 0) return rows[0];
        return false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const addInfrastructureConfigurations = async (
    deploymentId,
    infrastructureId,
    configurations,
) => {
    try {
        const rows = await apiFetch(
            `/deployments/${deploymentId}/infrastructure/${infrastructureId}`,
            "PUT",
            {
                configurations,
            },
        );

        if (rows.length > 0) return rows[0];
        return false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const deleteInfrastructure = async (deploymentId, infrastructureId) => {
    try {
        await apiFetch(
            `/deployments/${deploymentId}/infrastructure/${infrastructureId}`,
            "DELETE",
        );
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};
