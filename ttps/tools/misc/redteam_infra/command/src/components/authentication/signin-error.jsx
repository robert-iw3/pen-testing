"use client";

import { useSearchParams } from "next/navigation";

export function SigninError() {
    const searchParams = useSearchParams();
    const error = searchParams.get("error");

    if (error) {
        return (
            <p className="text-sm text-center text-red-500">
                {error === "CredentialsSignin"
                    ? "Incorrect email address or password."
                    : "An unknown error occured."}
            </p>
        );
    }
}
