import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { auth } from "./auth";

export function cn(...inputs) {
    return twMerge(clsx(inputs));
}

export async function apiFetch(path, method = "GET", body) {
    const session = await auth();
    if (!path) return false;

    if (body !== undefined) body = JSON.stringify(body);

    const response = await fetch(
        `http://nucleus:${process.env.NUCLEUS_PORT}${path}`,
        {
            method,
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${session?.accessToken}`,
            },
            body,
        },
    );

    if (!response.ok) return false;

    const contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("application/json") !== -1)
        return await response.json();

    return true;
}

export const copyToClipboard = async (value) => {
    await navigator.clipboard.writeText(value);
};
