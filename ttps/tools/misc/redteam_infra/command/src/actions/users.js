"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addUser = async (name, email, role, password, confirmPassword) => {
    try {
        if (
            await apiFetch("/users", "POST", {
                name,
                email,
                role,
                password,
                confirmPassword,
            })
        )
            return true;
        return false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};

export const deleteUser = async (id) => {
    try {
        if (await apiFetch(`/users/${id}`, "DELETE")) return true;
        return false;
    } catch (e) {
        console.log(e);
        throw new Error(e);
    } finally {
        revalidatePath("/settings", "layout");
    }
};
