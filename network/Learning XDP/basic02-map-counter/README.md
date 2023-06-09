# Basic02 - counting with BPF maps

The program is designed to be attached to an XDP (eXpress Data Path) hook, which is a high-performance data path in the Linux kernel for fast packet processing. 

The **goal** of this program is to **count the number of packets that pass through the XDP hook and store the statistics in a BPF hash map.**

# BPF Maps
  eBPF maps are a generic data structure for storage of different data types.They allow sharing of data between eBPF kernel programs, and also between kernel and user-space applications.
  Using eBPF maps is a method to keep state between invocations of the eBPF program, and allows sharing data between eBPF kernel programs, and also between kernel and user-space applications.


  Each map type has the following attributes:


       *  type

       *  maximum number of elements

       *  key size in bytes

       *  value size in bytes

It is defined in [tools/lib/bpf/libbpf.c](https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/libbpf.c#L479), line 479 (as a struct)`

```C
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
```
## Map type 
Currently, the following values are supported for `type` defined at `/usr/include/linux/bpf.h`

```C
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	/* BPF_MAP_TYPE_CGROUP_STORAGE is available to bpf programs attaching
	 * to a cgroup. The newer BPF_MAP_TYPE_CGRP_STORAGE is available to
	 * both cgroup-attached and other progs and supports all functionality
	 * provided by BPF_MAP_TYPE_CGROUP_STORAGE. So mark
	 * BPF_MAP_TYPE_CGROUP_STORAGE deprecated.
	 */
	BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE,
	BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER,
	BPF_MAP_TYPE_USER_RINGBUF,
	BPF_MAP_TYPE_CGRP_STORAGE,
};
```
map_type selects one of the available map implementations in the kernel.For all map types, eBPF programs access maps with the same `bpf_map_lookup_elem()` and `bpf_map_update_elem()` helper functions.

## Key Size
This field specifies the size of the key in the map, in bytes.
* The key is used to index the values stored in the map.
*  The key can be a scalar type or a structure, but it must fit within the specified size.
* The `sizeof(__u32)` specifies the size of the map keys. In this case, the keys are 32-bit unsigned integers.

## Value Size

This field specifies the size of the value in the map, in bytes.
* The value is the data that is stored in the map at each key.
* Like the key, the value can be a scalar type or a structure, but it must fit within the specified size.
* The `sizeof(struct datarec)` specifies the size of the map values. 
* In this case, the values are structs of type struct datarec.

## Max Entries

 This field specifies the maximum number of entries that the map can hold.
 *  This is the maximum number of key-value pairs that can be stored in the map.
 * This number is set at map creation time and cannot be changed later.
 * In this case, the maximum number of entries is `XDP_ACTION_MAX`, which is a constant defined

## Map flags

 This field specifies additional flags that control the behavior of the map.
 *  For example, the BPF_F_NO_PREALLOC flag can be used to indicate that the kernel shouldgit  not pre-allocate memory for the map, which can save memory in certain scenarios.

___
___

# Interacting with maps

Interacting with eBPF maps happens through some **lookup/update/delete** primitives.

## Userspace

The userspace API map helpers for eBPF are defined in tools/lib/bpf/bpf.h and include the following functions:

```C

/* Userspace helpers */
int bpf_map_lookup_elem(int fd, void *key, void *value);
int bpf_map_update_elem(int fd, void *key, void *value, __u64 flags);
int bpf_map_delete_elem(int fd, void *key);
/* Only userspace: */
int bpf_map_get_next_key(int fd, void *key, void *next_key);
```

* To interact with an eBPF map from userspace, you use the [bpf](https://man7.org/linux/man-pages/man2/bpf.2.html) syscall and a `file descriptor (fd)`. The `fd` serves as the **map handle**. 
* On success, these functions return zero, while on failure they return -1 and set errno.
* The wrappers for the bpf syscall are implemented in [tools/lib/bpf/bpf.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf/bpf.c) and call functions in [kernel/bpf/syscall.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/syscall.c), such as map_lookup_elem.
* It's worth noting that `void *key` and `void *value` are passed as void pointers. 
* This is because of the memory separation between kernel and userspace, and it involves making a copy of the value. 
* Kernel primitives like `copy_from_user()` and `copy_to_user()` are used for this purpose, as seen in [map_lookup_elem](https://elixir.bootlin.com/linux/latest/source/kernel/bpf/syscall.c#L1327), which also allocates and deallocates memory using `kmalloc+kfree` for a short period.
* From userspace, there is no direct function call to increment or decrement the value in-place. 
* Instead, the bpf_map_update_elem() call will overwrite the existing value with a copy of the value supplied. 
* The overwrite operation depends on the map type and may happen atomically using locking mechanisms specific to the map type.

## Kernel-side eBPF program
The eBPF program helpers for kernel-side interaction with maps are defined in the [samples/bpf/bpf_helpers.h](https://elixir.free-electrons.com/linux/v4.2.8/source/samples/bpf/bpf_helpers.h#L11) header file and are implemented in the [kernel/bpf/helpers.c](https://elixir.free-electrons.com/linux/v4.2.8/source/kernel/bpf/helpers.c#L29) file via macros.

```C
/* eBPF program helpers */
void *bpf_map_lookup_elem(void *map, void *key);
int bpf_map_update_elem(void *map, void *key, void *value, unsigned long long flags);
int bpf_map_delete_elem(void *map, void *key);
```


* The `bpf_map_lookup_elem()` function is a **kernel-side helper function** that allows eBPF programs to directly access the value stored in a map by providing a pointer to the map and a pointer to the key.
* Unlike the userspace API, which provides a copy of the value, the kernel-side API provides a **direct pointer** to the memory element inside the kernel where the value is stored.
* This allows eBPF programs to perform **atomic** operations, such as incrementing or decrementing the value "in-place", using appropriate compiler primitives like `__sync_fetch_and_add()`, which are understood by LLVM (Low-Level Virtual Machine) when generating eBPF instructions. 
* This direct access to the value memory element in the kernel provides more efficient and optimized access to map data structures for eBPF programs running in the kernel. So, the `bpf_map_lookup_elem()` function in the kernel-side eBPF API enables efficient and direct access to map values from eBPF programs running in the kernel.
_____
_____

## bpf_map_lookup_elem

[bpf_map_lookup_elem](https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/bpf.c#L398) is a function in the Linux kernel's BPF subsystem that is used to look up an element in a BPF map. 
* BPF maps are key-value data structures that can be used by BPF programs running in the Linux kernel to store and retrieve data.

The `bpf_map_lookup_elem` function takes two arguments:

1. `map`: A pointer to the BPF map to perform the lookup on.
1. `key`: A pointer to the key used to look up the element in the map.

The function **returns a pointer** to the value associated with the given key in the BPF map if the key is found, or `NULL` if the key is not found.

The function signature for `bpf_map_lookup_elem`:

```C
void *bpf_map_lookup_elem(void *map, const void *key);
```
In our program, `bpf_map_lookup_elem()` the helper function provided by the eBPF API that is used to look up an element in the BPF map. It takes two arguments:

```C
rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
```
1.  `&xdp_stats_map`: A **pointer** to the BPF map (struct bpf_map_def) that we want to perform the lookup on. In this case, it refers to the `xdp_stats_map` BPF map that was defined earlier in the code.
1.  `&key`: A **pointer** to the `key` that you want to look up in the map. The key is of `type __u32` and its value is determined by the variable key in the code, which is set to `XDP_PASS`.

The `bpf_map_lookup_elem()` function **returns a pointer** to the value associated with the given key in the BPF map `(&xdp_stats_map)`. 
* In other words, it allows you to retrieve the value stored in the BPF map corresponding to the key `XDP_PASS` and store it in the `rec` variable, which is of `type struct datarec` and represents the data record stored in the map.
* Note that if the lookup fails (i.e., the key does not exist in the map), the function may return `NULL`, and it's important to perform a **null pointer** check, as shown in the code, to ensure the safety and correctness of the eBPF program.

```C
	if (!rec)
		return XDP_ABORTED;
```

* Code  `if (!rec)` is checking if the value of the pointer `rec` is `NULL` or not. 
* If `rec` is `NULL`, it means that the lookup operation using `bpf_map_lookup_elem()` function failed, and the corresponding entry for the given `key` was not found in the BPF map `xdp_stats_map`.
* The function returns `XDP_ABORTED` as the return value.

___
___

The program defines a BPF hash map named **xdp_stats_map** to store the statistics. The map is an array with a size equal to **XDP_ACTION_MAX** (max entries), where each entry represents a different XDP action.

```C
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};
```
The XDP actions are enumerated in **enum xdp_action**,which is defined in `include/uapi/linux/bpf.h` and their values are XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, and XDP_REDIRECT. For each XDP action, a corresponding entry is created in the xdp_stats_map to store the number of packets that are associated with that action.

```C
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};
```

___
___
### __sync_fetch_and_add

```C
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif
```

We define a macro `lock_xadd` that wraps the `__sync_fetch_and_add` function using the GCC built-in function `__sync_fetch_and_add` for performing an atomic fetch-and-add operation on a given memory location.
* The macro takes two arguments: a pointer ptr to the target memory location, and a value val to be added to the current value of the memory location.
* `__sync_fetch_and_add` is a **built-in** GCC (GNU Compiler Collection) function that provides an atomic operation for fetching the current value of a memory location, adding a value to it, and storing the result back into the same memory location in a single, uninterruptible step. 
* This function is typically used in multi-threaded or concurrent programming to safely update shared variables without race conditions or other synchronization issues
* The macro definition simply wraps the `__sync_fetch_and_add` function call with an additional `(void)` cast to suppress any potential warnings about unused results, as the function returns the previous value of the memory location before the addition, which might not be used in some cases.

### lock_xadd

```C
	lock_xadd(&rec->rx_packets, 1);
```
The `lock_xadd()` function is used to **atomically increment** the value of `rec->rx_packets` by `1`.
* This operation ensures that the **increment** is performed **atomically**, meaning that it is thread-safe and can be safely used in a multi-CPU environment where multiple threads may be accessing the same memory location simultaneously. 
* The purpose of this operation is to **increment** the packet count in the `rx_packets` field of the `struct datarec` data record, which is stored in the `xdp_stats_map` BPF map.
* This allows the eBPF program to keep **track of the number of packets** that pass through the **XDP hook**
* Once the packet count is updated, the eBPF program may return `XDP_PASS` to indicate that the packet should be allowed to continue processing by the kernel networking stack. 
___
___

### xdp_stats1_func

The main function in the program is `xdp_stats1_func`, which is the actual XDP hook function.
* This function is executed whenever a packet passes through the XDP hook.

* The function first retrieves the data record associated with the XDP_PASS action from the xdp_stats_map using the `bpf_map_lookup_elem()` function.
* If the lookup is successful, the function increments the packet counter associated with the `XDP_PASS` action using an atomic add operation `(lock_xadd())`.


____
____

## common_kern_user.h

The `common_kern_user.h` header file is used by both the kernel-side BPF programs and userspace programs to share common structures and definitions.

### struct datarec

In this specific case, the `struct datarec` is defined in `common_kern_user.h` as a data record that will be stored in a BPF map. 
* It has a single field `rx_packets` of type `__u64`, which is an unsigned 64-bit integer that represents the **number of received packets.**

### XDP_ACTION_MAX

The `XDP_ACTION_MAX` is also defined in `common_kern_user.h` and represents the **maximum number of actions** that can be performed by an XDP (eXpress Data Path) program. 
* It is defined as `XDP_REDIRECT + 1`, where `XDP_REDIRECT` .
* `XDP_REDIRECT` is a predefined constant that represents the maximum value of the enum xdp_action enumeration, which is an enum used to define different actions that can be taken by an XDP (eXpress Data Path) program in the Linux kernel.
```C
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};
```
* In the provided code, the value of `XDP_REDIRECT` is used as the **maximum number of entries** in the `xdp_stats_map` BPF array map, which is used to store statistics for each possible XDP action. 
* By setting `XDP_REDIRECT + 1` as the **maximum number of entries**, the `xdp_stats_map` array map will have enough space to store statistics for all possible XDP actions, including `XDP_REDIRECT`.
* Therefore, the value of `XDP_REDIRECT` is used to determine the size of the array map and ensure that it has enough entries to accommodate all possible actions.
