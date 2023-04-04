//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") xdp_stats_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size =sizeof(struct datarec),
    .max_entries = XDP_ACTION_MAX
};

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{


}