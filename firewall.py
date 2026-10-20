#!/usr/bin/env python3
"""
 ============================================================================
 Project Name : eBPF + XDP High-Performance Firewall (User-Space Control Plane)
 Author       : Soumik Debnath
 Description  : Python management script using BCC (BPF Compiler Collection).
                Features:
                - Pixel-perfect aligned startup banner & author metadata.
                - Root/Sudo privilege validation.
                - Active daemon startup guard (prevents duplicate instances & fresh-start overrides).
                - Flexible network interface selection (-i).
                - Background Daemon Mode (-b / --background) with true process forking & terminal release.
                - Graceful Stop (--stop) support.
                - In-shell 'bg' command with true Unix process forking.
                - Automatic JSON disk persistence for manual blocklists across restarts.
                - Interactive REPL shell with command history (Up/Down arrows via readline).
                - Built-in 'help', 'clear', and 'bg' commands.
                - Kernel-synchronized audit logging for DDoS attacks with alert debouncing.
                - Robust Ctrl+C safety guard to prevent accidental shutdowns.
                - Canonical session deduplication for clean stateful connection tables.
 ============================================================================
"""

from bcc import BPF
import socket
import struct
import ctypes
import sys
import argparse
import os
import signal
import time
import json
import readline
from datetime import datetime

PID_FILE = ".firewall.pid"
BLOCKLIST_FILE = ".blocklist.json"

# --- 0. HANDLE --stop ARGUMENT FIRST ---
if len(sys.argv) == 2 and sys.argv[1] == "--stop":
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            print(f"[+] Sent termination signal to background firewall (PID: {pid}).")
        except ProcessLookupError:
            print("[-] Background firewall process not found (stale PID file). Cleaning up.")
            os.remove(PID_FILE)
        except Exception as e:
            print(f"[-] Error stopping firewall: {e}")
    else:
        print("[-] No active background firewall PID file found.")
    sys.exit(0)

# --- 1. PRIVILEGE VERIFICATION GUARD ---
if os.geteuid() != 0:
    print("\n" + "="*70)
    print("[!] Error: Ultimate XDP Firewall requires root/sudo privileges to load eBPF/XDP programs.")
    print("[!] Please run the script using: sudo python3 firewall.py")
    print("="*70 + "\n")
    sys.exit(1)

# --- 2. ACTIVE DAEMON STARTUP GUARD ---
if os.path.exists(PID_FILE):
    try:
        with open(PID_FILE, "r") as f:
            existing_pid = int(f.read().strip())
        os.kill(existing_pid, 0)
        print("\n" + "═" * 70)
        print(f"  [!] ERROR: Ultimate XDP Firewall is already running in the background!")
        print(f"      Active Daemon PID : {existing_pid}")
        print(f"      Action Required   : Please stop it first using:")
        print(f"                          sudo python3 firewall.py --stop")
        print("═" * 70 + "\n")
        sys.exit(1)
    except ProcessLookupError:
        os.remove(PID_FILE)
    except Exception:
        os.remove(PID_FILE)

# --- 3. COMMAND-LINE ARGUMENT PARSING ---
parser = argparse.ArgumentParser(
    description="Ultimate eBPF + XDP Firewall Control Plane",
    epilog="Example usage: sudo python3 firewall.py -i eth0 -b"
)
parser.add_argument("-i", "--interface", default="lo", help="Network interface to attach XDP program (default: lo)")
parser.add_argument("-b", "--background", action="store_true", help="Run firewall in background daemon mode")
args = parser.parse_args()

INTERFACE = args.interface
IS_BACKGROUND = args.background

# --- 4. KERNEL COMPILATION & XDP ATTACHMENT ---
print(f"[-] Compiling and loading Ultimate XDP Firewall on interface: {INTERFACE}...")
b = BPF(src_file="firewall_kern.c")
fn = b.load_func("xdp_firewall_prog", BPF.XDP)
b.attach_xdp(INTERFACE, fn, 0)

blocklist_map = b["blocklist"]
ratelimit_map = b["ratelimit_map"]
conn_track_map = b["conn_track"]

# Helper functions for IP conversion
def ip_to_hex(ip_str):
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def hex_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

# --- PERSISTENCE: LOAD SAVED BLOCKLIST ON STARTUP ---
def load_persistent_blocklist():
    if os.path.exists(BLOCKLIST_FILE):
        try:
            with open(BLOCKLIST_FILE, "r") as f:
                ips = json.load(f)
                for ip_str in ips:
                    ip_key = ip_to_hex(ip_str)
                    c_key = ctypes.c_uint(ip_key)
                    c_val = ctypes.c_uint(1)
                    blocklist_map[c_key] = c_val
                print(f"[+] Loaded {len(ips)} persistent blocked IP(s) from disk.")
        except Exception as e:
            print(f"[-] Error loading persistent blocklist: {e}")

# Load any previously saved blocks into the kernel map
load_persistent_blocklist()

# Audit & History structures
attack_history = []
last_logged_windows = {}

# --- GRACEFUL SIGNAL CLEANUP HANDLER ---
def cleanup_and_exit(sig, frame):
    print(f"\n[!] Detaching XDP program from interface [{INTERFACE}]...")
    try:
        b.remove_xdp(INTERFACE, 0)
    except Exception:
        pass
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
    print("[+] Firewall successfully stopped cleanly.")
    sys.exit(0)

# Register signal handlers for clean termination (supports kill, --stop, and Ctrl+C)
signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

# --- 5. STARTUP BANNER ---
banner_width = 68
print("\n┌" + "─" * banner_width + "┐")
print("│         ULTIMATE eBPF + XDP HIGH-PERFORMANCE FIREWALL ENGINE       │")
print("│                     Production Security Suite                      │")
print("├" + "─" * banner_width + "┤")
print(f"│ Author : Soumik Debnath".ljust(banner_width + 1) + "│")
print(f"│ Status : ACTIVE & Monitoring Network Driver [{INTERFACE}]".ljust(banner_width + 1) + "│")
if IS_BACKGROUND:
    print(f"│ Mode   : Running in BACKGROUND daemon mode.                     │")
    #print(f"│ Stop   : Run 'sudo python3 firewall.py --stop' to terminate.    │")
else:
    print(f"│ Mode   : Interactive REPL Shell Enabled.                           │")
print(f"│ Tips   : Run 'sudo python3 firewall.py --help' for CLI options.    │")
print(f"│          Type 'help' inside the interactive prompt for commands.   │")
print("└" + "─" * banner_width + "┘" + "\n")
print("[i] Live kernel debug pipe: sudo cat /sys/kernel/debug/tracing/trace_pipe\n")

# --- 6. EXECUTION MODES (BACKGROUND VS INTERACTIVE) ---

if IS_BACKGROUND:
    try:
        # Fork the process to detach and release the terminal immediately
        pid = os.fork()
        if pid > 0:
            # Parent process: Write child PID to file and exit cleanly, releasing terminal
            with open(PID_FILE, "w") as f:
                f.write(str(pid))
            print(f"[+] Ultimate XDP Firewall successfully backgrounded (Daemon PID: {pid}).")
            print("[+] Terminal released. To terminate later, run: sudo python3 firewall.py --stop\n")
            sys.exit(0)
    except OSError as e:
        print(f"[-] Fork failed: {e}")
        sys.exit(1)
    
    # Child daemon process: Sets new session and runs silently in background
    os.setsid()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup_and_exit(None, None)
else:
    # Interactive REPL Command Loop
    try:
        while True:
            try:
                cmd_input = input("firewall> ").strip()
            except KeyboardInterrupt:
                print("\n[!] To exit the firewall control plane, please type 'exit' or type 'bg' to background.\n")
                continue

            if not cmd_input:
                continue
            
            parts = cmd_input.split()
            action = parts[0].lower()

            if action == "exit":
                print("\n[+] Exiting firewall control plane...")
                break
            elif action in ["bg", "background"]:
                print("\n[+] Transitioning active session into background daemon mode...")
                try:
                    pid = os.fork()
                    if pid > 0:
                        with open(PID_FILE, "w") as f:
                            f.write(str(pid))
                        print(f"[+] Firewall successfully backgrounded (Daemon PID: {pid}).")
                        print("[+] Terminal released. To terminate later, run: sudo python3 firewall.py --stop\n")
                        sys.exit(0)
                except OSError as e:
                    print(f"[-] Fork failed: {e}\n")
                    continue
                
                os.setsid()
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    cleanup_and_exit(None, None)
            elif action == "clear":
                os.system('clear')
            elif action == "help":
                print("\n" + "="*50)
                print("Available Firewall Commands:")
                print("  block <IP>       -> Manually block an IP address")
                print("  remove <IP>      -> Unblock an IP address")
                print("  list             -> View manually blocked IPs")
                print("  rates            -> View live trackers & kernel-synced audit logs")
                print("  connections      -> View active stateful TCP sessions")
                print("  bg / background  -> Move interactive session to background")
                print("  clear            -> Clear the terminal screen")
                print("  help             -> Display this help menu")
                print("  exit             -> Stop firewall and exit")
                print("="*50 + "\n")
            elif action == "list":
                print("\n--- Manual Blocklist ---")
                count = 0
                for k, v in blocklist_map.items():
                    print(f"  - {hex_to_ip(k.value)}")
                    count += 1
                if count == 0:
                    print("  (No manually blocked IPs)")
                print("-" * 24 + "\n")
            elif action == "rates":
                current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for k, v in ratelimit_map.items():
                    if v.packet_count > 100:
                        ip_str = hex_to_ip(k.value)
                        current_kernel_window = v.last_time
                        should_log = True
                        if ip_str in last_logged_windows:
                            if last_logged_windows[ip_str] == current_kernel_window:
                                should_log = False
                        if should_log:
                            event = {
                                "timestamp": current_time_str,
                                "ip": ip_str,
                                "rate": v.packet_count
                            }
                            attack_history.insert(0, event)
                            last_logged_windows[ip_str] = current_kernel_window

                print("\n--- Active Rate-Limit Trackers (Current Window) ---")
                active_count = 0
                for k, v in ratelimit_map.items():
                    print(f"  - IP: {hex_to_ip(k.value)} | Packets in window: {v.packet_count}")
                    active_count += 1
                if active_count == 0:
                    print("  (No active traffic tracked)")
                print("-" * 45)

                print("\n--- DDoS / Flood Attack Audit Log (Latest First) ---")
                if len(attack_history) == 0:
                    print("  (No rate-limit violations or DDoS spikes recorded yet)")
                else:
                    for idx, ev in enumerate(attack_history[:10]):
                        print(f"  [{idx+1}] Time: {ev['timestamp']} | IP: {ev['ip']} | Rate: {ev['rate']} pkts/sec [DROPPED]")
                print("-" * 52 + "\n")
            elif action == "connections":
                print("\n--- Active Stateful Connection Table ---")
                seen_sessions = set()
                count = 0
                for k, v in conn_track_map.items():
                    src_str = hex_to_ip(k.src_ip)
                    dst_str = hex_to_ip(k.dst_ip)
                    src_p = socket.ntohs(k.src_port)
                    dst_p = socket.ntohs(k.dst_port)
                    endpoint_a = (k.src_ip, k.src_port)
                    endpoint_b = (k.dst_ip, k.dst_port)
                    session_signature = tuple(sorted([endpoint_a, endpoint_b]))
                    if session_signature not in seen_sessions:
                        seen_sessions.add(session_signature)
                        print(f"  - {src_str}:{src_p} <-> {dst_str}:{dst_p} [ESTABLISHED]")
                        count += 1
                if count == 0:
                    print("  (No active TCP sessions tracked)")
                print("-" * 38 + "\n")
            elif action in ["block", "remove"] and len(parts) == 2:
                ip_addr = parts[1]
                try:
                    ip_key = ip_to_hex(ip_addr)
                    c_key = ctypes.c_uint(ip_key)
                    c_val = ctypes.c_uint(1)
                    if action == "block":
                        blocklist_map[c_key] = c_val
                        # Save to disk persistence file
                        try:
                            ips = [hex_to_ip(k.value) for k in blocklist_map.keys()]
                            with open(BLOCKLIST_FILE, "w") as f:
                                json.dump(ips, f)
                        except Exception:
                            pass
                        print(f"[+] Successfully blocked IP: {ip_addr} (Persisted to disk)\n")
                    elif action == "remove":
                        if c_key in blocklist_map:
                            del blocklist_map[c_key]
                            try:
                                ips = [hex_to_ip(k.value) for k in blocklist_map.keys()]
                                with open(BLOCKLIST_FILE, "w") as f:
                                    json.dump(ips, f)
                            except Exception:
                                pass
                            print(f"[+] Successfully unblocked IP: {ip_addr} (Updated on disk)\n")
                        else:
                            print(f"[-] IP {ip_addr} was not found in the blocklist.\n")
                except socket.error:
                    print(f"[-] Invalid IP address format: {ip_addr}\n")
            else:
                print("[-] Invalid command. Type 'help' to see available commands.\n")
    except EOFError:
        print("\n[!] EOF received.")

# Trigger clean shutdown on exit from interactive loop
cleanup_and_exit(None, None)
