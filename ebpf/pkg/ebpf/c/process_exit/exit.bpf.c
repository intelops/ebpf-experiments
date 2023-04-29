//go:build ignore

/**
*	Type: package
*	Name: process_entry
*	Description: This is a kernel space program.
*
*
*	Authors: Charan Ravela
*	Created Date: 04-19-2023
*	Last Modified: 04-19-2023
 */

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_SIZE 256

struct event_data{
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __s32 syscall_nr;
    __s64 ret;


    __u8 comm[16];
    __u8 cwd[32];
};

//Force emits struct event_data into the elf.
const struct event_data *unused __attribute__((unused));

//sys_exit_execve data structure
//can be found at below path
// /sys/kernel/debug/tracing/events/syscalls/sys_exit_execve/format
struct execve_exit_struct{
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;

    __s32 syscall_nr;
    __s64 ret;
};

//Map Definition
struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

//Null bytes
static char zero[MAX_SIZE] SEC(".rodata") = {0};

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_exit(struct execve_exit_struct *ctx){

    struct event_data *ed;
    ed = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0);
    if (!ed){
        return 0;
    }
    
    s64 res;

    //Syscall number
    ed->syscall_nr = ctx->syscall_nr;

    //Return value
    ed->ret = ctx->ret;

    //Process Id and Thread Group Id
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ed->pid = pid_tgid >> 32;
    ed->tgid = pid_tgid;

    //User Id and Group Id
    __u64 uid_gid = bpf_get_current_uid_gid();
    ed->uid = uid_gid >> 32;
    ed->gid = uid_gid;

    // Command trigred event
    bpf_get_current_comm(&ed->comm, sizeof(ed->comm));

    //Current Working Directory
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs;
    struct dentry *dentry;

    bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &fs->pwd.dentry);
    res = bpf_probe_read_kernel_str(&ed->cwd, sizeof(ed->cwd), &dentry->d_iname);
    if(res < 0) {
        bpf_ringbuf_discard(ed, 0);
        return 1;
    }

    //pushes the information to ringbuf event mamp
    bpf_ringbuf_submit(ed, 0);
    
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";

