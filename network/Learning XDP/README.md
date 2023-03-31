# eBPF-XDP-playground
Learning eBPF programming for XDP hooks

XDP (eXpress Data Path) is a technology in the Linux kernel that enables high-performance packet processing at the earliest possible stage of network I/O. XDP programs are implemented using eBPF (Extended Berkeley Packet Filter), a virtual machine that executes custom programs within the kernel. XDP programs are executed before the kernel's networking stack, allowing for low-level packet processing with minimal overhead.

XDP programs can be used to implement a variety of network functions, including:

Packet filtering: XDP programs can be used to selectively drop or allow packets based on various criteria, such as source/destination addresses or protocols.
Load balancing: XDP programs can be used to distribute incoming traffic across multiple network interfaces or backend servers.
Traffic monitoring: XDP programs can be used to collect statistics or logs on incoming network traffic.
