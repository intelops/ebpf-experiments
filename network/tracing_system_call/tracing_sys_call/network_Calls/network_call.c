//go:build ignore
#include "common.h"
#include <bpf/bpf_core_read.h>
#include <asm/ptrace.h>

#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->rsp)
#define PT_REGS_FP(x) ((x)->rbp)
#define PT_REGS_RC(x) ((x)->rax)
#define PT_REGS_SP(x) ((x)->rsp)
#define PT_REGS_IP(x) ((x)->rip)

#define _SYS_CONNECT 42
#define _SYS_SOCKET 41
#define _SYS_CONNECT 42
#define _SYS_ACCEPT 43
#define _SYS_BIND 49
#define _SYS_LISTEN 50

char __license[] SEC("license") = "Dual MIT/GPL";
//create a structure to store event metadata

 #define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct bpf_map_def SEC("maps") _name = {                        \
        .type = _type,                                              \
        .key_size = sizeof(_key_type),                              \
        .value_size = sizeof(_value_type),                          \
        .max_entries = _max_entries,                                \
    };
#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240)

struct event
{
    unsigned long args[6];
}args_t;


 BPF_HASH(args_map_socket, u64, args_t);  
 BPF_HASH(args_map_connect, u64, args_t);  
BPF_HASH(args_map_listen, u64, args_t); 
BPF_HASH(args_map_bind, u64, args_t); 
 BPF_HASH(args_map_accept, u64, args_t); 

SEC("kprobe/__x64_sys_socket")
int __x64_sys_socket(struct pt_regs *ctx) // og had kprobe__connect
{
 struct event args_t = {};

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args_t.args[0], sizeof(args_t.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args_t.args[1], sizeof(args_t.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args_t.args[2], sizeof(args_t.args[2]), &PT_REGS_PARM3(ctx2));

    bpf_printk("Socket Domain : %d\n",args_t.args[0]);
    bpf_printk("Socket type: %d\n", args_t.args[1]);
    bpf_printk("Socket protocol: %d\n", args_t.args[2]);


    u32 tgid = bpf_get_current_pid_tgid();
   // u64 id = ((u64)event_id << 32) | tgid;
    bpf_printk("tgid: %d\n",tgid);
    //bpf_printk("id: %d\n",id) ;

    bpf_map_update_elem(&args_map_socket, &tgid, &args_t, BPF_ANY);

    return 0;
  
}


SEC("kprobe/__x64_sys_connect")
int __x64_sys_connect(struct pt_regs *ctx) // og had kprobe__connect
{  
           struct event args_t = {};

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args_t.args[0], sizeof(args_t.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args_t.args[1], sizeof(args_t.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args_t.args[2], sizeof(args_t.args[2]), &PT_REGS_PARM3(ctx2));

    bpf_printk("Connect filedes : %d\n",args_t.args[0]);
    bpf_printk("Connect Addr: %d\n", args_t.args[1]);
    bpf_printk("Connect Addrlen: %d\n", args_t.args[2]);


    u32 tgid = bpf_get_current_pid_tgid();
   // u64 id = ((u64)event_id << 32) | tgid;
    bpf_printk("tgid: %d\n",tgid);
   // bpf_printk("id: %d\n",id) ;

    bpf_map_update_elem(&args_map_connect, &tgid, &args_t, BPF_ANY);

    return 0;
}

SEC("kprobe/__x64_sys_listen")
int __x64_sys_listen(struct pt_regs *ctx) //  had kprobe__connect
{  
  struct event args_t = {};

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    
    bpf_probe_read(&args_t.args[0], sizeof(args_t.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args_t.args[1], sizeof(args_t.args[1]), &PT_REGS_PARM2(ctx2));
  

    u32 tgid = bpf_get_current_pid_tgid();
   // u64 id = ((u64)event_id << 32) | tgid;
    bpf_printk("tgid: %d\n",tgid);
    //bpf_printk("id: %d\n",id) ;
   bpf_printk("Listen Socket Fd : %d\n",args_t.args[0]);
    bpf_printk("Listen backlog: %d\n", args_t.args[1]);



    bpf_map_update_elem(&args_map_listen, &tgid, &args_t, BPF_ANY);

    return 0;

}

SEC("kprobe/__x64_sys_accept")
int __x64_sys_accept(struct pt_regs *ctx) //  had kprobe__connect
{  
  struct event args_t = {};

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    
    bpf_probe_read(&args_t.args[0], sizeof(args_t.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args_t.args[1], sizeof(args_t.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args_t.args[2], sizeof(args_t.args[2]), &PT_REGS_PARM3(ctx2));




    u32 tgid = bpf_get_current_pid_tgid();
   // u64 id = ((u64)event_id << 32) | tgid;
    bpf_printk("tgid: %d\n",tgid);
    //bpf_printk("id: %d\n",id) ;

    bpf_printk("Accept Socket Fd : %d\n",args_t.args[0]);
    bpf_printk("Accept Socket raw Address: %d\n", args_t.args[1]);
    bpf_printk("Accept Socket Address length: %p\n", args_t.args[2]);



    bpf_map_update_elem(&args_map_accept, &tgid, &args_t, BPF_ANY);

    return 0;
}


SEC("kprobe/__x64_sys_bind")
int __x64_sys_bind(struct pt_regs *ctx) //  had kprobe__connect
{  
  struct event args_t = {};

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    
    bpf_probe_read(&args_t.args[0], sizeof(args_t.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args_t.args[1], sizeof(args_t.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args_t.args[2], sizeof(args_t.args[2]), &PT_REGS_PARM3(ctx2));




    u32 tgid = bpf_get_current_pid_tgid();
    //u64 id = ((u64)event_id << 32) | tgid;
    bpf_printk("tgid: %d\n",tgid);
   // bpf_printk("id: %d\n",id) ;


    bpf_printk("Bind Socket Fd : %d\n",args_t.args[0]);
    bpf_printk("Bind Socket raw Address: %d\n", args_t.args[1]);
    bpf_printk("Bind Socket Address length: %p\n", args_t.args[2]);


    bpf_map_update_elem(&args_map_bind, &tgid, &args_t, BPF_ANY);

    return 0;
}


