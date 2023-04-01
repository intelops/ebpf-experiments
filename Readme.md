# eBPF Programs for Container Security
This repository contains a collection of eBPF programs designed for enhancing the observability and security of containerized environments. These programs can be used to monitor network traffic, detect and prevent attacks, and enforce security policies in real-time.

## Getting Started
To use these eBPF programs, you'll need a Linux kernel that supports eBPF. Additionally, you'll need to have the appropriate tools installed for compiling and loading eBPF programs. Once you have these prerequisites in place, you can clone this repository and start using the programs right away.

## Program Descriptions
Each program in this repository is designed to address a specific security or observability use case in containerized environments. Here are some examples:

network-traffic-monitor: This program monitors network traffic and reports on various metrics such as total bytes transferred, top talkers, and protocol distribution.

process-execution-monitor: This program monitors process execution and reports on various metrics such as process start time, command-line arguments, and parent process ID.

network-socket-monitor: This program monitors network sockets and reports on various metrics such as socket type, protocol, and local and remote endpoints.

## Roadmap

Process execution monitoring: Develop an eBPF program that can track process execution and report on various metrics such as process start time, command-line arguments, and parent process I
D
Network socket monitoring: Develop an eBPF program that can monitor network sockets and report on various metrics such as socket type, protocol, and local and remote endpoints.

File system monitoring: Develop an eBPF program that can monitor file system activities within containers, such as file creation, modification, and deletion.

Network identity tracking: Develop an eBPF program that can track the network identity of containers and enforce network policies based on identity.

## Contributing
If you have an idea for a new eBPF program or want to contribute to an existing program, we welcome your contributions! Please submit a pull request with your changes and we'll review them as soon as possible.

## License
All eBPF programs in this repository are licensed under the MIT license. See the LICENSE file for more details.


## Acknowledgments
We would like to thank the eBPF community for their contributions and support.
