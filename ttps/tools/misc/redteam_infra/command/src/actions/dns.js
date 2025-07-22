"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const createDnsRecord = async (type, name, value, domainId) => {
    try {
        await apiFetch(`/domains/${domainId}/dns`, "POST", {
            type,
            name,
            value,
        });
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};

export const deleteDnsRecord = async (domainId, id) => {
    try {
        await apiFetch(`/domains/${domainId}/dns/${id}`, "DELETE");
        return true;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/", "layout");
    }
};
