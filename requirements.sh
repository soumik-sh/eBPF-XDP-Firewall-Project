#!/bin/bash
# ============================================================================
# Script Name : requirements.sh
# Description : Dependency installation and environment preparation script for
#               the eBPF + XDP High-Performance Firewall project.
# Author      : Soumik Debnath
# ============================================================================

set -e

# --- 1. PRIVILEGE VERIFICATION ---
if [ "$EUID" -ne 0 ]; then
    echo "[!] Error: This script requires root/sudo privileges to install kernel headers and BCC tools."
    echo "[!] Please run using: sudo ./requirements.sh"
    exit 1
fi

echo "[+] Starting eBPF/XDP firewall environment setup..."

# --- 2. UPDATE SYSTEM PACKAGE LISTS ---
echo "[+] Updating apt package repositories..."
apt-get update -y

# --- 3. INSTALL COMPILERS, HEADERS, AND BUILD DEPENDENCIES ---
# Resolves missing Clang/LLVM compilation errors and kernel header mismatches
echo "[+] Installing Clang, LLVM, libbpf, and matching kernel headers..."
apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    python3 \
    python3-pip \
    python3-dev \
    git

# --- 4. INSTALL BCC (BPF COMPILER COLLECTION) ---
# Resolves missing bcc Python bindings and header path errors
echo "[+] Installing BCC tools and Python 3 bindings..."
apt-get install -y \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev

# --- 5. VERIFY DEBUGFS MOUNT ---
# eBPF trace_pipe relies on debugfs being active
if [ ! -d "/sys/kernel/debug/tracing" ]; then
    echo "[+] Mounting kernel debugfs..."
    mount -t debugfs debugfs /sys/kernel/debug/
fi

# --- 6. VALIDATE PYTHON BCC BINDINGS ---
echo "[+] Validating BCC Python module import..."
python3 -c "import bcc; print('[+] Success: BCC Python module loaded correctly!')"

echo "============================================================================"
echo "[+] All dependencies have been successfully installed and verified!"
echo "[+] You can now launch the firewall using: sudo python3 firewall.py"
echo "============================================================================"