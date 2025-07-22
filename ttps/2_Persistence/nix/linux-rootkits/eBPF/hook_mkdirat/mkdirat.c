#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_mkdirat")
int kprobe__do_mkdirat(struct pt_regs *ctx)
{
    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);
    const char *dirname = BPF_CORE_READ(name, name);

    bpf_printk("New directory created: %s", dirname);

    return 0;
}
