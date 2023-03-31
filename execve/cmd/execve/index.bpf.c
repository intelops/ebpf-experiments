//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") event = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

//sys_enter_execve data structure
//can be found at below path
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct execve_struct
{
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;

    __s32 syscall_nr;
    __u8 const *filename;
    __u8 *const argv;
    __u8 *const envp;
};

//
struct event_data
{
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __s32 syscall_nr;
    __u8 comm[80];
    __u8 filename[256];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int ebpf_execve(struct execve_struct *ctx){
    struct event_data ed = {};

    ed.syscall_nr = ctx->syscall_nr;

    //reads filename    
    bpf_probe_read_user(&ed.filename, sizeof(&ed.comm), ctx->filename);
    
    //fetch current command
    bpf_get_current_comm(&ed.comm, sizeof(&ed.comm));

    __u64 pid_tgid = bpf_get_current_pid_tgid();  
    ed.pid = pid_tgid >> 32;
    ed.tgid = pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    ed.uid = uid_gid >> 32;
    ed.gid = uid_gid;

    //pushes the information to perf event map
    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &ed, sizeof(ed));

    return 0;
};

char _license[] SEC("license") = "Dual MIT/GPL";