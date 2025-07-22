#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_unlinkat")
int kprobe__sys_unlinkat(struct pt_regs *regs)
{
    bpf_printk("hooked unlinkat");

    struct filename *name = (struct filename *)PT_REGS_PARM2(regs);
    const char *filename = BPF_CORE_READ(name, name);

    bpf_printk("intercepted filename: %s", filename);

    return 0;
}
