# eBPF + Security: High-Performance XDP Firewall

**Author:** Soumik Debnath

**Tags:** `eBPF` `Linux` `Networking` `XDP` `Security` `Firewall` `Daemon`

---

## Table of Contents

1. [Introduction](#introduction)
2. [Problem Statement](#problem-statement)
3. [Levels](#levels)
4. [Architecture: The 4-Tier Security Pipeline](#architecture-the-4-tier-security-pipeline)
5. [Control Plane & Daemonization Features](#control-plane--daemonization-features)
6. [Installation & Environment Setup](#installation--environment-setup)
7. [Quick Start](#quick-start)
8. [Testing & Cross-Checking Guide](#testing--cross-checking-guide)
9. [Background & Lifecycle Management Commands](#background--lifecycle-management-commands)
10. [Resources](#resources)
11. [Mentor Details](#mentor-details)

---

## Introduction

Extended Berkeley Packet Filter (eBPF) allows you to run custom, sandboxed programs inside the Linux kernel. By utilizing eXpress Data Path (XDP), network packets can be processed and dropped at the lowest possible layer—often before the kernel allocates an `sk_buff`—making it a powerful tool for building high-performance, low-latency firewalls.

This project implements a programmable, 4-tier high-performance firewall engine comprising a kernel-space C program (`firewall_kern.c`) and a user-space Python control plane (`firewall.py`).

---

## Problem Statement

Build a **programmable, high-performance firewall using eBPF and XDP**.

You will start with a basic stateless packet dropper and independently research how to evolve it into a dynamic, rate-limiting security tool.

The goal is to explore the **kernel-to-user-space boundary** and understand **raw packet processing**.

---

## Levels

### Level 1: Stateless Firewall

- Research how to attach an XDP program to a network interface and safely read packet headers.
- Write a kernel-space program to intercept incoming traffic and drop packets based on a hardcoded rule. Example: Block all ICMP requests, block a specific protocol.
- Log the dropped packet details to the trace pipe for basic observability.

### Level 2: Dynamic Control Plane

- Hardcoding rules requires recompiling the kernel code, which isn't practical.
- Explore how to share data and state between **kernel space and user space**.
- Build a simple user-space command-line tool using **Go, Python, or C** that allows an administrator to:
    - Add blocked IP addresses dynamically.
    - Remove blocked IP addresses dynamically.
    - View currently blocked IP addresses.
    - Apply changes on the fly **without reloading the XDP program**.

### Level 3: Rate Limiting & DDoS Mitigation

- Enhance the firewall to detect and mitigate volumetric attacks such as a **TCP SYN flood**.
- Figure out how to track packet rates and timestamps per source IP. If an IP exceeds a predefined threshold (e.g., > 100 packets per second), automatically drop subsequent packets from that source.
- The firewall should:
    - Track packet rates per source IP.
    - Track timestamps per source IP.
    - Define a packet-rate threshold.
    - Automatically drop subsequent packets from a source IP when the threshold is exceeded.

**Example:** If an IP exceeds **100 packets per second**, automatically drop subsequent packets from that source.

### Level 4: Stateful Connection Tracking

- Stateless firewalls are easily bypassed. Research how to track the state of active network connections.
- Monitor outgoing connections and modify your firewall so that it only permits inbound traffic if it belongs to a locally initiated session. Drop all unsolicited inbound traffic.
- Modify the firewall to:
    - Monitor outgoing connections.
    - Track the state of active network connections.
    - Permit inbound traffic only if it belongs to a **locally initiated session**.
    - Drop all unsolicited inbound traffic.

---

## Architecture: The 4-Tier Security Pipeline

The firewall evaluates packets through a rigorous 4-tier security pipeline at the network driver level:

```text
[ Incoming Packet ] ──> [ Level 1: Bounds Check & L2/3 Parsing ]
                                │
                                ▼
                       [ Level 2: Manual Blocklist ] ──(Dropped if Blocked)
                                │
                                ▼
                       [ Level 3: Rate Limiter (>100 pkts/sec) ] ──(Dropped on Flood)
                                │
                                ▼
                       [ Level 4: Stateful TCP 4-Tuple Tracking ] ──(Dropped if Unsolicited)
                                │
                                ▼
                        [ XDP_PASS / ALLOW ]
```

- **Level 1 (Packet Ingestion & Parsing):** Verifies strict packet memory boundaries (`data` to `data_end`) to satisfy the eBPF verifier, parses Ethernet Layer 2 headers (`ETH_P_IP`), and validates IPv4 headers.
- **Level 2 (Manual Blocklist):** Performs fast O(1) BPF hash map lookups (`blocklist`) to drop traffic from manually blocked source IP addresses instantly. Blocked states automatically persist to disk (`.blocklist.json`).
- **Level 3 (Rate Limiting & DDoS Mitigation):** Tracks traffic velocities per source IP over a sliding time window using high-precision monotonic kernel timestamps (`bpf_ktime_get_ns()`). If traffic exceeds 100 packets per second, subsequent packets are automatically dropped.
- **Level 4 (Stateful TCP Connection Tracking):** Inspects transport-layer TCP headers (`IPPROTO_TCP`) and maintains a bidirectional 4-tuple session table (`conn_track`). Inbound traffic is permitted only if it belongs to a locally initiated session or active handshake, with bidirectional garbage collection clearing entries on `FIN` or `RST` flags.

---

## Control Plane & Daemonization Features

The user-space Python management script (`firewall.py`) provides robust production features:

- **Interactive REPL Shell:** Features command history (Up/Down arrow support via `readline`), `help`, `clear`, and live statistics commands.
- **Active Daemon Startup Guard:** Checks `.firewall.pid` on startup to prevent duplicate instances or accidental overrides of active XDP hooks.
- **Background Daemon Mode:** Supports both command-line (`-b` / `--background`) and in-shell (`bg`) execution via Unix process forking (`os.fork()` and `os.setsid()`) to release the terminal safely.
- **Graceful Termination:** Run `sudo python3 firewall.py --stop` to cleanly detach the XDP program from the network interface and clear active lock files.

---

## Installation & Environment Setup

### Prerequisites & Dependencies (`requirements.sh`)

To install all required compilers, BCC tools, and kernel headers without errors, use the following setup script:

```bash
#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run using sudo: sudo ./requirements.sh"
    exit 1
fi

echo "[+] Updating system packages..."
apt-get update -y

echo "[+] Installing build essentials, Clang, LLVM, libbpf, and kernel headers..."
apt-get install -y build-essential clang llvm libbpf-dev linux-headers-$(uname -r) python3 python3-pip python3-dev git

echo "[+] Installing BCC tools and Python 3 bindings..."
apt-get install -y bpfcc-tools python3-bpfcc libbpfcc-dev

if [ ! -d "/sys/kernel/debug/tracing" ]; then
    mount -t debugfs debugfs /sys/kernel/debug/
fi

python3 -c "import bcc; print('[+] BCC Python module verified successfully!')"
echo "[+] Setup completed successfully!"
```

---

## Quick Start

1. Run the setup script with root permissions:

    ```bash
    sudo ./requirements.sh
    ```

2. Launch the firewall interactively on the loopback interface (`lo`):

    ```bash
    sudo python3 firewall.py -i lo
    ```

3. Alternatively, launch directly as a background daemon:

    ```bash
    sudo python3 firewall.py -i lo -b
    ```

---

## Testing & Cross-Checking Guide

### Testing Level 1 & Level 2 (Manual Blocklist & Persistence)

- **Verification Command:**

    ```bash
    ping -c 3 127.0.0.1
    ```

- **REPL Actions:**

    - Inside the interactive shell (`firewall>`), block the local IP:

        ```text
        firewall> block 127.0.0.1
        ```

    - View active blocks:

        ```text
        firewall> list
        ```

    - Re-run `ping -c 3 127.0.0.1` to confirm packets are dropped. Rules are automatically written to `.blocklist.json`.

    - Unblock when finished:

        ```text
        firewall> remove 127.0.0.1
        ```

### Testing Level 3 (Rate Limiting & DDoS Mitigation)

- **Flood Simulation Command:**

    ```bash
    ping -f 127.0.0.1
    ```

- **REPL Actions:** Check live trackers and debounced attack logs:

    ```text
    firewall> rates
    ```

    (Stop the flood test using `Ctrl+C`).

### Testing Level 4 (Stateful Connection Tracking)

- **Testing Established TCP Sessions:**

    - Open a netcat listener:

        ```bash
        nc -l 8080
        ```

    - Connect from another terminal:

        ```bash
        nc 127.0.0.1 8080
        ```

    - Inspect active tracked sessions in the REPL:

        ```text
        firewall> connections
        ```

- **Testing Failed Connection Teardown (RST):**

    - Attempt to connect to an unopened port:

        ```bash
        nc -zv 127.0.0.1 9999
        ```

    - Verify that the connection table remains clean without false-positive `[ESTABLISHED]` states due to bidirectional garbage collection.

---

## Background & Lifecycle Management Commands

- Move active session to background from REPL:

    ```text
    firewall> bg
    ```

- Stop the running background daemon:

    ```bash
    sudo python3 firewall.py --stop
    ```

---

## Resources

- [eBPF](https://ebpf.io/)
- XDP Tutorial (GitHub)
- L4Drop — XDP DDoS Mitigations
- _Learning eBPF_ by Liz Rice (Book)
- [Gemini AI](https://gemini.google.com/)

---

## Mentor Details

1. Shanjiv – shanjiv.231cs155@nitk.edu.in
2. Nishant – nishant.231ee138@nitk.edu.in
