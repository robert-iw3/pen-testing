"use server";

import { apiFetch } from "@/lib/utils";
import { revalidatePath } from "next/cache";

export const addFile = async (name, extension, value, variables) => {
  try {
    const file = await apiFetch("/files", "POST", {
      name,
      value,
      variables,
      extension,
    });

    return file;
  } catch (e) {
    console.log(e);
    throw new Error(e);
  } finally {
    revalidatePath("/settings", "layout");
  }
};

export const updateFile = async (id, name, extension, value, variables) => {
  try {
    const file = await apiFetch(`/files/${id}`, "PUT", {
      name,
      extension,
      value,
      variables,
    });

    return file;
  } catch (e) {
    console.log(e);
    throw new Error(e);
  } finally {
    revalidatePath("/settings", "layout");
  }
};

export const deleteFile = async (id) => {
  try {
    await apiFetch(`/files/${id}`, "DELETE");
    return true;
  } catch (e) {
    console.log(e);
    throw new Error(e);
  } finally {
    revalidatePath("/settings", "layout");
  }
};
