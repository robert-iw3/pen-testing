"use server";

import { signIn } from "@/lib/auth";
import { AuthError } from "next-auth";
import { redirect } from "next/navigation";
import { refreshData } from "./util";

export const authenticate = async (formData) => {
    try {
        await signIn("credentials", formData);
        return true;
    } catch (error) {
        if (error instanceof AuthError) {
            redirect(`/auth/signin?error=${error.type}`);
        }
        return false;
    } finally {
        refreshData();
    }
};
