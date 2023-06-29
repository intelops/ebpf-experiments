//go:build ignore
#include "common.h"
#include <bpf/bpf_core_read.h>
#include <asm/ptrace.h>


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

#define BPF_LRU_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, 10240)

#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024)

struct event
{
    unsigned long args[6];
}args_t;

typedef struct buffers
{
    u8 buf[MAX_BUFFER_SIZE];
} bufs_t;

typedef struct __attribute__((__packed__)) sys_context
{
    u64 ts;

    u32 pid_id;
    u32 mnt_id;

    u32 host_ppid;
    u32 host_pid;

    u32 ppid;
    u32 pid;
    u32 uid;

    u32 event_id;
    u32 argnum;
    s64 retval;

    char comm[TASK_COMM_LEN];
} sys_context_t;

BPF_HASH(args_map, u64, args_t);   
BPF_PERCPU_ARRAY(bufs, bufs_t, 3);
BPF_PERCPU_ARRAY(bufs_offset, u32, 3); 
BPF_PERF_OUTPUT(sys_events);




static __always_inline int save_args(u32 event_id, struct pt_regs *ctx)
{
    struct event args = {};

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args.args[2], sizeof(args.args[2]), &PT_REGS_PARM3(ctx2));

    bpf_printk("Socket Domain probed : %d\n",args.args[0]);
    bpf_printk("Socket type probed: %d\n", args.args[1]);
    bpf_printk("Socket protocol probed: %d\n", args.args[2]);


    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)event_id << 32) | tgid;
    bpf_printk("tgid probed: %d\n",tgid);
    bpf_printk("id probed: %d\n",id) ;

    bpf_map_update_elem(&args_map, &id, &args, BPF_ANY);

    return 0;
}



static __always_inline int load_args(u32 event_id,struct event * args)
{
    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)event_id << 32) | tgid;

    struct event *saved_args = bpf_map_lookup_elem(&args_map, &id);
    if (saved_args == 0)
    {
        return -1; // missed entry or not a container
    }

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    bpf_map_delete_elem(&args_map, &id);

    return 0;
}

/**
static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->parent);
    return READ_KERN(parent->pid);
}
**/
static __always_inline bufs_t *get_buffer(int buf_type)
{
    return bpf_map_lookup_elem(&bufs, &buf_type);
}

static __always_inline u32 *get_buffer_offset(int buf_type)
{
    return bpf_map_lookup_elem(&bufs_offset, &buf_type);
}

static __always_inline u32 init_context(sys_context_t *context)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    context->ts = bpf_ktime_get_ns();
    //context->host_ppid = get_task_ppid(task);
    context->host_pid = bpf_get_current_pid_tgid() >> 32;
    context->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&context->comm, sizeof(context->comm));

    return 0;
}


static __always_inline int get_arg_num(u64 types)
{
    unsigned int i, argnum = 0;

#pragma unroll
    for (i = 0; i < MAX_ARGS; i++)
    {
        if (DEC_ARG_TYPE(i, types) != NONE_T)
            argnum++;
    }

    return argnum;
}

static __always_inline void set_buffer_offset(int buf_type, u32 off)
{
    bpf_map_update_elem(&bufs_offset, &buf_type, &off, BPF_ANY);
}

static __always_inline int save_context_to_buffer(bufs_t *bufs_p, void *ptr)
{
    if (bpf_probe_read(&(bufs_p->buf[0]), sizeof(sys_context_t), ptr) == 0)
    {
        return sizeof(sys_context_t);
    }

    return 0;
}

static __always_inline int save_to_buffer(bufs_t *bufs_p, void *ptr, int size, u8 type)
{
// the biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    if (type == 0)
    {
        return 0;
    }

    u32 *off = get_buffer_offset(DATA_BUF_TYPE);
    if (off == NULL)
    {
        return -1;
    }

    if (*off > MAX_BUFFER_SIZE - MAX_ELEMENT_SIZE)
    {
        return 0;
    }

    if (bpf_probe_read(&(bufs_p->buf[*off]), 1, &type) != 0)
    {
        return 0;
    }

    *off += 1;

    if (*off > MAX_BUFFER_SIZE - MAX_ELEMENT_SIZE)
    {
        return 0;
    }

    if (bpf_probe_read(&(bufs_p->buf[*off]), size, ptr) == 0)
    {
        *off += size;
        set_buffer_offset(DATA_BUF_TYPE, *off);
        return size;
    }

    return 0;
}


static __always_inline int save_args_to_buffer(u64 types, struct event *args)
{
    if (types == 0)
    {
        return 0;
    }

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
    {
        return 0;
    }

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++)
    {
        switch (DEC_ARG_TYPE(i, types))
        {
        case NONE_T:
            break;
        case INT_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), INT_T);
            break;
        case OPEN_FLAGS_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), OPEN_FLAGS_T);
            break;
        //case FILE_TYPE_T:
           // save_file_to_buffer(bufs_p, (void *)args->args[i]);
            //break;
        case PTRACE_REQ_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), PTRACE_REQ_T);
            break;
        case MOUNT_FLAG_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), MOUNT_FLAG_T);
            break;
        case UMOUNT_FLAG_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), UMOUNT_FLAG_T);
            break;
       // case STR_T:
         //   save_str_to_buffer(bufs_p, (void *)args->args[i]);
           // break;
        case SOCK_DOM_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), SOCK_DOM_T);
            break;
        case SOCK_TYPE_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), SOCK_TYPE_T);
            break;
        case SOCKADDR_T:
            if (args->args[i])
            {
                short family = 0;
                bpf_probe_read(&family, sizeof(short), (void *)args->args[i]);
                switch (family)
                {
                case AF_UNIX:
                    save_to_buffer(bufs_p, (void *)(args->args[i]), sizeof(struct sockaddr_un), SOCKADDR_T);
                    break;
                case AF_INET:
                    save_to_buffer(bufs_p, (void *)(args->args[i]), sizeof(struct sockaddr_in), SOCKADDR_T);
                    break;
                case AF_INET6:
                    save_to_buffer(bufs_p, (void *)(args->args[i]), sizeof(struct sockaddr_in6), SOCKADDR_T);
                    break;
                default:
                    save_to_buffer(bufs_p, (void *)&family, sizeof(short), SOCKADDR_T);
                }
            }
            break;
        case UNLINKAT_FLAG_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), UNLINKAT_FLAG_T);
            break;
        }
    }

    return 0;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx)
{
    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return -1;

    u32 *off = get_buffer_offset(DATA_BUF_TYPE);
    if (off == NULL)
        return -1;

    void *data = bufs_p->buf;
    int size = *off & (MAX_BUFFER_SIZE - 1);

    return bpf_perf_event_output(ctx, &sys_events, BPF_F_CURRENT_CPU, data, size);
}

static __always_inline int trace_ret_generic(u32 id, struct pt_regs *ctx, u64 types, u32 scope)
{
    //if (skip_syscall())
      //  return 0;


    sys_context_t context = {};
    struct event args = {};

    if (ctx == NULL)
        return 0;

    if (load_args(id, &args) != 0)
        return 0;

    init_context(&context);

    context.event_id = id;
        bpf_printk(" event_id kretprobe : %d\n",context.event_id);

    context.argnum = get_arg_num(types);
    bpf_printk(" argnum kretprobe : %d\n",context.argnum);
    context.retval = PT_REGS_RC(ctx);
    bpf_printk("retval kretprobe : %d\n",context.retval);

    // skip if No such file/directory or if there is an EINPROGRESS
    // EINPROGRESS error, happens when the socket is non-blocking and the connection cannot be completed immediately.
    if (context.retval == -2 || context.retval == -115)
    {
        return 0;
    }

    //if (context.retval >= 0 && drop_syscall(scope))
   //{
   //   return 0;
  // }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &args);
    events_perf_submit(ctx);
    return 0;
}


SEC("kprobe/__x64_sys_socket")
int __x64_sys_socket(struct pt_regs *ctx) 
{
    bpf_printk("=====================Enter kprobe %s=======================",__func__);
    return save_args(_SYS_SOCKET, ctx);
    bpf_printk("=====================Exit : %s=======================",__func__);
}

SEC("kprobe/__x64_sys_connect")
int __x64_sys_connect(struct pt_regs *ctx) 
{
 bpf_printk("=====================Enter kprobe: %s=======================",__func__);
    return save_args(_SYS_CONNECT, ctx);
       bpf_printk("=====================Exit : %s=======================",__func__);
}

SEC("kprobe/__x64_sys_accept")
int __x64_sys_accept(struct pt_regs *ctx) 
{
 bpf_printk("=====================Enter kprobe: %s=======================",__func__);
    return save_args(_SYS_ACCEPT, ctx);
       bpf_printk("=====================Exit : %s=======================",__func__);
}

SEC("kprobe/__x64_sys_bind")
int __x64_sys_bind(struct pt_regs *ctx) 
{
 bpf_printk("=====================Enter kprobe: %s=======================",__func__);
    return save_args(_SYS_BIND, ctx);
   bpf_printk("=====================Exit : %s=======================",__func__);
}

SEC("kprobe/__x64_sys_listen")
int __x64_sys_listen(struct pt_regs *ctx) 
{
 bpf_printk("=====================Enter kprobe: %s=======================",__func__);
    return save_args(_SYS_LISTEN, ctx);
   bpf_printk("=====================Exit : %s=======================",__func__);
}


SEC("kretprobe/__x64_sys_socket")
int sys_socket(struct pt_regs *ctx) 
{
     bpf_printk("=====================Enter kretprobe: %s=======================",__func__);
    return trace_ret_generic(_SYS_SOCKET, ctx, ARG_TYPE0(SOCK_DOM_T) | ARG_TYPE1(SOCK_TYPE_T) | ARG_TYPE2(INT_T), _NETWORK_PROBE);
   bpf_printk("=====================Exit : %s=======================",__func__);
}

SEC("kretprobe/__x64_sys_connect")
int sys_connect(struct pt_regs *ctx)
{
     bpf_printk("=====================Enter kretprobe: %s=======================",__func__);
    return trace_ret_generic(_SYS_CONNECT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T), _NETWORK_PROBE);
       bpf_printk("=====================Exit : %s=======================",__func__);
}


SEC("kretprobe/__x64_sys_accept")
int sys_accept(struct pt_regs *ctx)
{
     bpf_printk("=====================Enter kretprobe: %s=======================",__func__);
    return trace_ret_generic(_SYS_ACCEPT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T), _NETWORK_PROBE);
       bpf_printk("=====================Exit : %s=======================",__func__);
}

SEC("kretprobe/__x64_sys_bind")
int sys_bind(struct pt_regs *ctx)
{
     bpf_printk("=====================Enter kretprobe: %s=======================",__func__);
    return trace_ret_generic(_SYS_BIND, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T), _NETWORK_PROBE);
       bpf_printk("=====================Exit : %s=======================",__func__);
}

SEC("kretprobe/__x64_sys_listen")
int sys_listen(struct pt_regs *ctx)
{
     bpf_printk("=====================Enter kretprobe: %s=======================",__func__);
    return trace_ret_generic(_SYS_LISTEN, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(INT_T), _NETWORK_PROBE);
       bpf_printk("=====================Exit : %s=======================",__func__);
}

static __always_inline int get_connection_info(struct sock_common *conn, struct sockaddr_in *sockv4, struct sockaddr_in6 *sockv6, sys_context_t *context, struct event *args, u32 event)
{
    switch (conn->skc_family)
    {
    case AF_INET:
        sockv4->sin_family = conn->skc_family;//Sets the address family 
        sockv4->sin_addr.s_addr = conn->skc_daddr;//Copies the destination IP address
        sockv4->sin_port = (event == _TCP_CONNECT) ? conn->skc_dport : (conn->skc_num >> 8) | (conn->skc_num << 8);//
        args->args[1] = (unsigned long)sockv4;
        context->event_id = (event == _TCP_CONNECT) ? _TCP_CONNECT : _TCP_ACCEPT;
        break;

    case AF_INET6:
        sockv6->sin6_family = conn->skc_family;
        sockv6->sin6_port = (event == _TCP_CONNECT) ? conn->skc_dport : (conn->skc_num >> 8) | (conn->skc_num << 8);
        bpf_probe_read(&sockv6->sin6_addr.in6_u.u6_addr16, sizeof(sockv6->sin6_addr.in6_u.u6_addr16), conn->skc_v6_daddr.in6_u.u6_addr16);
        args->args[1] = (unsigned long)sockv6;
        context->event_id = (event == _TCP_CONNECT) ? _TCP_CONNECT_v6 : _TCP_ACCEPT_v6;
        break;

    default:
        return 1;
    }

    return 0;
}


SEC("kprobe/__x64_sys_tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
    bpf_printk("=====================Enter krpobe: %s=======================",__func__);
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sock_common conn = READ_KERN(sk->__sk_common);
    struct sockaddr_in sockv4;
    struct sockaddr_in6 sockv6;

    sys_context_t context = {};
    struct event args = {};
    u64 types = ARG_TYPE0(STR_T) | ARG_TYPE1(SOCKADDR_T);

    init_context(&context);
    context.argnum = get_arg_num(types);
    bpf_printk(" tcp_connect argnum : %d\n",context.argnum);
    context.retval = PT_REGS_RC(ctx);
     bpf_printk(" tcp_connect retval : %d\n",context.retval);

   // if (context.retval >= 0 && drop_syscall(_NETWORK_PROBE))
   if (context.retval >= 0 )
   {
      return 0;
   }

    if (get_connection_info(&conn, &sockv4, &sockv6, &context, &args, _TCP_CONNECT) != 0)
    {
        return 0;
    }

    args.args[0] = (unsigned long)conn.skc_prot->name;
    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));
    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;
    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &args);
    events_perf_submit(ctx);

    return 0;
}

SEC("kretprobe/__x64_sys_inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
   // if (skip_syscall())
     //   return 0;
bpf_printk("=====================Enter krpobe: %s=======================",__func__);
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (newsk == NULL)
        return 0;

    // Code from https://github.com/iovisor/bcc/blob/master/tools/tcpaccept.py with adaptations
    u16 protocol = 1;
    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    if (sk_lingertime_offset - gso_max_segs_offset == 2)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
        protocol = READ_KERN(newsk->sk_protocol);
#else
        protocol = newsk->sk_protocol;
#endif
    else if (sk_lingertime_offset - gso_max_segs_offset == 4)
    // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_gso_max_segs - 3));
    else
        // pre-4.10 with little endian
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_wmem_queued - 3));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 4.10+ with big endian
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_gso_max_segs - 1));
    else
        // pre-4.10 with big endian
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_wmem_queued - 1));
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

    if (protocol != IPPROTO_TCP)
        return 0;

    struct sock_common conn = READ_KERN(newsk->__sk_common);
    struct sockaddr_in sockv4;
    struct sockaddr_in6 sockv6;
    sys_context_t context = {};
    struct event args = {};
    u64 types = ARG_TYPE0(STR_T) | ARG_TYPE1(SOCKADDR_T);
    init_context(&context);
    context.argnum = get_arg_num(types);
    context.retval = PT_REGS_RC(ctx);

    //if (context.retval >= 0 && drop_syscall(_NETWORK_PROBE))
   // {
     //   return 0;
   // }

    if (get_connection_info(&conn, &sockv4, &sockv6, &context, &args, _TCP_ACCEPT) != 0)
    {
        return 0;
    }

    args.args[0] = (unsigned long)conn.skc_prot->name;
    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));
    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &args);
    events_perf_submit(ctx);

    return 0;
}
