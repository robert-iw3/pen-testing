"use server";

import { revalidatePath } from "next/cache";

export const refreshData = async () => {
    revalidatePath("/", "layout");
};
