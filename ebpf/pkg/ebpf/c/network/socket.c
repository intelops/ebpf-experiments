//go:build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"


#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)


char __license[] SEC("license") = "Dual MIT/GPL";
//create a structure to store event metadata


 struct event{
 __u32 family;
__u32 type;
int protocol;
};

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/__x64_sys_socket")
int __x64_sys_socket(struct pt_regs *ctx) {
    struct event args = {};
    
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    bpf_probe_read(&args.family, sizeof(args.family), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.type, sizeof(args.type), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args.protocol, sizeof(args.protocol), &PT_REGS_PARM3(ctx2));

bpf_printk("Socket Domain: %d\n", args.family);
bpf_printk("Socket Type: %d\n", args.type);
bpf_printk("Socket Protocol: %d\n", args.protocol);
struct event *task_info;

task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
if (!task_info) {
return 0;
}
*task_info = args;
bpf_ringbuf_submit(task_info, 0);
return 0;

}