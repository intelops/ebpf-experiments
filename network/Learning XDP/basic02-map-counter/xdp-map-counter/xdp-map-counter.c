//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") xdp_stats_map =
{
    .type = BPF_



}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{


}