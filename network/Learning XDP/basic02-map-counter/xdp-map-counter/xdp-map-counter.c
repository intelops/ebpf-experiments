//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") xdp_stats_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size =sizeof(struct datarec),
    .max_entries = XDP_ACTION_MAX,
};
//definiton of map 

#ifndef lock_xadd
#define lock_xadd(ptr,val) ((void) __sync_fetch_and_add(ptr,val))
#endif
//using GNU built in __sync_fetch_and_add for sync and adding to bpf map values

SEC("xdp_stats1")
int xdp_stats1_func(struct xdp_md *ctx)
{
    struct datarec *rec;
    ___u32 key = XDP_PASS;
    rec = bpf_map_lookup_elem()


}
