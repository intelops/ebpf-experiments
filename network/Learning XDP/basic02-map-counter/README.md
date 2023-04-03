# Basic02 - counting with BPF maps

The program is designed to be attached to an XDP (eXpress Data Path) hook, which is a high-performance data path in the Linux kernel for fast packet processing. 

The **goal** of this program is to **count the number of packets that pass through the XDP hook and store the statistics in a BPF hash map.**

The program defines a BPF hash map named **xdp_stats_map** to store the statistics. The map is an array with a size equal to **XDP_ACTION_MAX** (max entries), where each entry represents a different XDP action.

```C
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};
```
. The XDP actions are enumerated in **enum xdp_action**,which is defined in `include/uapi/linux/bpf.h` and their values are XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, and XDP_REDIRECT. For each XDP action, a corresponding entry is created in the xdp_stats_map to store the number of packets that are associated with that action.

```C
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};
```

### xdp_stats1_func

The main function in the program is `xdp_stats1_func`, which is the actual XDP hook function.
* This function is executed whenever a packet passes through the XDP hook.

* The function first retrieves the data record associated with the XDP_PASS action from the xdp_stats_map using the `bpf_map_lookup_elem()` function.
* If the lookup is successful, the function increments the packet counter associated with the `XDP_PASS` action using an atomic add operation `(lock_xadd())`.





