# Roadmap to learn eBPF


### 1. What Is eBPF, and Why Is It Important? 

Learning eBPF by Liz Rice

 - The Linux Kernel
 - Kernel Modules
 - Dynamic Loading of eBPF Programs
 - High Performance of eBPF Programs
 - eBPF in Cloud Native Environments


### 2. eBPF’s “Hello World”  

(Refer Learning eBPF
by  Liz Rice )

- "Hello world with userspace program  in GO"
-  Running “Hello World”
- BPF Maps
  -  Hash Table Map
  - Perf and Ring Buffer Maps
  - Function Calls
  - Tail Calls



###  Running Your First BPF Programs

Refer
 (Linux Observability with BPF
 by  David Calavera and Lorenzo Fontana)
 
- Writing BPF Programs
- BPF Program Types
 Socket Filter Programs
 Kprobe Programs
 Tracepoint Programs
 XDP Programs
 Perf Event Programs
 Cgroup Socket Programs
 Cgroup Open Socket Programs
 Socket Option Programs
 Socket Map Programs
 Cgroup Device Programs
 Socket Message Delivery Programs
 Raw Tracepoint Programs
 Cgroup Socket Address Programs
 Socket Reuseport Programs
 Flow Dissection Programs
 Other BPF Programs

- The BPF Verifier
- BPF Type Format
- BPF Tail Calls

### 3. Anatomy of an eBPF Program

Learning eBPF by Liz Rice

 - The eBPF Virtual Machine
  - eBPF Registers
  - eBPF Instructions

- eBPF “Hello World” for a Network Interface
- Compiling an eBPF Object File
- Inspecting an eBPF Object File
- Loading the Program into the Kernel
- Inspecting the Loaded Program
  - The BPF Program Tag
  - The Translated Bytecode
  - The JIT-Compiled Machine Code
- Attaching to an Event
- Global Variables
- Detaching the Program
- Unloading the Program
- BPF to BPF Calls


### 4. The bpf() System Call 

Learning eBPF by Liz Rice

- Loading BTF Data
- Creating Maps
- Loading a Program
- Modifying a Map from User Space
- BPF Program and Map References
  - Pinning
  - BPF Links
 - Additional Syscalls Involved in eBPF
   - Initializing the Perf Buffer
   - Attaching to Kprobe Events
   - Setting Up and Reading Perf Events
- Ring Buffers
- Reading Information from a Map
 - Finding a Map
 - Reading Map Elements

### 5.CO-RE, BTF, and Libbpf

Learning eBPF by Liz Rice

- Approach to Portability
- CO-RE Overview
- BPF Type Format
  - BTF Use Cases
  - Listing BTF Information with bpftool
  - BTF Types
  - Maps with BTF Information
  - BTF Data for Functions and Function Prototypes
  - Inspecting BTF Data for Maps and Programs
- Generating a Kernel Header File
- CO-RE eBPF Programs
  - Header Files
     - Kernel header information
     - Headers from libbpf
     - Application-specific headers
 - Defining Maps
 - eBPF Program Sections
 - Memory Access with CO-RE
 - License Definition
- Compiling eBPF Programs for CO-RE
  - Debug Information
  - Optimization
  - Target Architecture
  - Makefile
  - BTF Information in the Object File
- BPF Relocations
- CO-RE User Space Code
- The Libbpf Library for User Space
  - BPF Skeletons
  - Code Examples


### 6. The eBPF Verifier

Learning eBPF by Liz Rice

- The Verification Process
- The Verifier Log
- Visualizing Control Flow
- Validating Helper Functions
- Helper Function Arguments
- Checking the License
- Checking Memory Access
- Checking Pointers Before Dereferencing Them
- Accessing Context
- Running to Completion
- Loops
- Checking the Return Code
- Invalid Instructions
- Unreachable Instructions


### 7.  eBPF Program and Attachment Types

Learning eBPF by Liz Rice

- Program Context Arguments
- Helper Functions and Return Codes
- Kfuncs
- Tracing
 - Kprobes and Kretprobes
      - Attaching kprobes to syscall entry points
   - Fentry/Fexit
 - Tracepoints
 - BTF-Enabled Tracepoints
 - User Space Attachments
 - LSM
- Networking
    - Sockets
    - Traffic Control
    - XDP
    - Flow Dissector
    - Lightweight Tunnels
    - Cgroups
    - Infrared Controllers
- BPF Attachment Types


### 8. Tracing with BPF

Refer  Linux Observability with BPF
 by  David Calavera and Lorenzo Fontana


- Probes
 - Kernel Probes
   Kprobes
   Kretprobes
 - Tracepoints
 - User-Space Probes
   Uprobes
    Uretprobes
 - User Statically Defined Tracepoints
- Visualizing Tracing Data
 - Flame graphs
 - Histograms
 - Perf Events

### 9. BPF Maps

Refer  Linux Observability with BPF
 by  David Calavera and Lorenzo Fontana

- Creating BPF Maps
- ELF Conventions to Create BPF Maps
- Working with BFP Maps
- Updating Elements in a BPF Map
- Reading Elements from a BPF Map
- Removing an Element from a BPF Map
- Looking Up and Deleting Elements
- Concurrent Access to Map Elements
- Types of BPF Maps
 - Hash-Table Maps
 - Array Maps
 - Program Array Maps
 - Perf Events Array Maps
 - Per-CPU Hash Maps
 - Per-CPU Array Maps
 - Stack Trace Maps
 - Cgroup Array Maps
 - LRU Hash and Per-CPU Hash Maps
 - LPM Trie Maps
 - Array of Maps and Hash of Maps
 - Device Map Maps
 - CPU Map Maps
 - Open Socket Maps
 - Socket Array and Hash Maps
 - Cgroup Storage and Per-CPU Storage Maps
 - Reuseport Socket Maps
 - Queue Maps
 - Stack Maps
- The BPF Virtual Filesystem

### 10.  eBPF for Networking

Learning eBPF by Liz Rice

- Packet Drops
     - XDP Program Return Codes
     - XDP Packet Parsing
- Load Balancing and Forwarding
- XDP Offloading
- Traffic Control (TC)
- Packet Encryption and Decryption
   - User Space SSL Libraries
- eBPF and Kubernetes Networking
   - Avoiding iptables
   - Coordinated Network Programs
   - Network Policy Enforcement
   - Encrypted Connections
- More resources

### Linux Networking and BPF

Refer  Linux Observability with BPF
 by  David Calavera and Lorenzo Fontana

- BPF and Packet Filtering
 - tcpdump and BPF Expressions
 - Packet Filtering for Raw Sockets
- BPF-Based Traffic Control Classifier
  - Terminology
   - Queueing disciplines
   - Classful qdiscs, filters, and classes
   - Classless qdiscs
   - Traffic Control Classifier Program Using cls_bpf
   - Differences Between Traffic Control and XDP
   - 
### 11. Express Data Path

Refer  Linux Observability with BPF
 by  David Calavera and Lorenzo Fontana
 
- XDP Programs Overview
 - Operation Modes
  - Native XDP
  - Offloaded XDP
  - Generic XDP
 - The Packet Processor
   - XDP result codes (packet processor actions)
   -  XDP and iproute2 as a Loader
- writing XDP program

 - Testing XDP Programs
  - XDP Testing Using the Python Unit Testing Framework

- XDP Use Cases
  - Monitoring
  - DDoS Mitigation
  - Load Balancing
  - Firewalling

###  12.Linux Kernel Security, Capabilities, and Seccomp

Refer  Linux Observability with BPF
 by  David Calavera and Lorenzo Fontana

- Capabilities
- Seccomp
 - Seccomp Errors
 - Seccomp BPF Filter Example
- BPF LSM Hooks


### 13. eBPF for Security

Learning eBPF by Liz Rice

- Security Observability Requires Policy and Context
- Using System Calls for Security Events
   - Seccomp
   - Generating Seccomp Profiles
   - Syscall-Tracking Security Tools
- BPF LSM
- TracingPolicy.
  - Attaching to Internal Kernel Functions
  - Preventative Security
- Network Security

### 14. eBPF Programming

Learning eBPF by Liz Rice

- Bpftrace
- Language Choices for eBPF in the Kernel
- BCC Python/Lua/C++
- C and Libbpf
   - Go
   - Gobpf
   - Ebpf-go
   - Libbpfgo
- Rust
   - Libbpf-rs
   - Redbpf
   - Aya
   - Rust-bcc
- Testing BPF Programs
- Multiple eBPF Programs

### 15. BPF Utilities

Refer  Linux Observability with BPF
 by  David Calavera and Lorenzo Fontana
 
 - BPFTool
 - BPFTrace
 - kubectl-trace
 - eBPF Exporter

#### 16. Security Observability with eBPF
Refer Security Observability with eBPF
by  Jed Salazar and Natalia Reka Ivanko

###  The Lack of Visibility

- What Should We Monitor?
- High-Fidelity Observability
- A Kubernetes Attack

###  Brief Guide to Container Security

look for better resource

- Kernel Namespaces
- Cgroups
- Attack Points for Container Escapes
- Linux Capabilities

###  17.Why Is eBPF the Optimal Tool for Security?

Refer Security Observability with eBPF
by  Jed Salazar and Natalia Reka Ivanko



- Precloud Security
- Monitoring from Legacy Kernel, Disk, and Network Tools
- A Cloud Native Approach
- Deep Dive into the Security of eBPF
  - Virtual Machine in the Kernel
  - eBPF Programs
  -  eBPF Hook Points
- Why eBPF?
   - System Call Visibility
   - Network Visibility
   - Filesystem Visibility
- The Underlying Host

### 18. Security Observability by eBPF

Refer Security Observability with eBPF
by  Jed Salazar and Natalia Reka Ivanko


-  The Four Golden Signals of Security Observability
-  Process Execution
-  Network Sockets
-  File Access
-  Layer 7 Network Identity

- Real-World Attack
 -  Stealthy Container Escape
 - Reaching The Host Namespace
 - Persistence
 - Post Exploitation Techniques

### 19.Security Prevention by eBPF

Refer Security Observability with eBPF
by  Jed Salazar and Natalia Reka Ivanko


- Prevention by Way of Least-Privilege
- Allowlist
- Denylist
- Testing Your Policy
- Tracing Policy
  - Stage 1: Exploitation
  - Stage 2: Persistence and Defense Evasion
  - Stage 3: Post-Exploitation
Data-Driven Security

### 20.  The Future Evolution of eBPF

Learning eBPF by Liz Rice

- The eBPF Foundation
- eBPF for Windows
- Linux eBPF Evolution
- eBPF Is a Platform, Not a Feature

