# eBPF-based Intrusion Detection System

This project is about to develop an IDS based totally in eBPF programs, in a way that improves execution times compared to other traditional technologies that process packets in user-space.

It is a part of a Masther's thesis whose objective is to show a modern alternative to intrusion detection with kernel-based network packet processing.

Currently, the project includes programs capable of detecting Denial of Service attacks through TCP flags.

## System specifications

+ OS: Kali 2025.1
+ Kernel Version: 6.12.25-amd64
+ Libbpf version: 1.5.0
