#!/usr/bin/env python3

import socket
import threading
import argparse
import sys
from queue import Queue
from datetime import datetime
import time
import ipaddress
from urllib.parse import urlparse
import ssl # For potential future HTTPS/TLS banner checks (more complex)

# --- Configuration ---
DEFAULT_THREADS = 1500
DEFAULT_TIMEOUT = 0.5 # Scan connection timeout
BANNER_TIMEOUT = 2.0  # Timeout for grabbing banner data (seconds)
BANNER_BUFSIZE = 1024 # Max bytes to read for banner
MAX_PORT = 65535
PRINT_LOCK = threading.Lock()

port_queue = Queue()
open_ports = [] # Stores tuples: (port, service_name) during scan if found quickly
# We will store final results in a dictionary: {port: {'service': name, 'banner': banner_str}}
final_results = {}

# --- Helper Functions ---
def print_status(message, flush=False):
    with PRINT_LOCK:
        sys.stdout.write(message + '\n')
        if flush:
            sys.stdout.flush()

def resolve_target(target_str, is_verbose): # Pass verbose flag
    original_target = target_str
    hostname = target_str

    if '://' in hostname:
        try:
            parsed_url = urlparse(hostname)
            hostname = parsed_url.netloc.split(':')[0]
            if not hostname:
                 print_status(f"[!] Invalid URL format: {original_target}")
                 return None, original_target
        except Exception as e:
             print_status(f"[!] Error parsing URL '{original_target}': {e}")
             hostname = target_str

    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_verbose:
            print_status(f"[*] Target resolved locally to IP: {hostname} (from input: {original_target})")
        return str(ip_obj), original_target
    except ValueError:
        pass # Not an IP, proceed to DNS

    if is_verbose:
        print_status(f"[*] Resolving hostname: {hostname} (from input: {original_target})")
    try:
        target_ip = socket.gethostbyname(hostname)
        if is_verbose:
             print_status(f"[+] Resolved '{hostname}' to IP: {target_ip}")
        return target_ip, original_target
    except socket.gaierror:
        print_status(f"[!] Error: Could not resolve hostname: {hostname}")
        return None, original_target
    except socket.error as e:
        print_status(f"[!] Network error during resolution for '{hostname}': {e}")
        return None, original_target

def parse_ports(port_spec):
    # (Function remains the same as before)
    ports = set()
    if not port_spec:
        print_status("[!] Error: No ports specified.")
        sys.exit(1)
    try:
        parts = port_spec.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (0 < start <= MAX_PORT and 0 < end <= MAX_PORT and start <= end):
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            else:
                port_num = int(part)
                if not (0 < port_num <= MAX_PORT):
                     raise ValueError(f"Invalid port number: {part}")
                ports.add(port_num)
    except ValueError as e:
        print_status(f"[!] Error parsing ports: {e}")
        print_status("[!] Example formats: 80 | 1-1024 | 22,80,443-445,8080")
        sys.exit(1)
    if not ports:
        print_status("[!] Error: Port specification resulted in empty set.")
        sys.exit(1)
    return sorted(list(ports))

# --- Banner Grabbing Logic ---
def grab_banner(target_ip, port, timeout):
    """Attempts to connect and read initial data (banner) from a port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout) # Use dedicated banner timeout
            sock.connect((target_ip, port))

            # Try receiving data immediately after connect
            # Some services send banner right away (FTP, SMTP, some SSH)
            try:
                # Set a specific receive timeout, could be different from connect timeout
                sock.settimeout(max(0.1, timeout / 2)) # Shorter timeout for recv
                banner_bytes = sock.recv(BANNER_BUFSIZE)

                if banner_bytes:
                    # Decode safely, replacing errors
                    banner = banner_bytes.decode('utf-8', errors='replace')
                    # Clean up common non-printable chars and excessive whitespace
                    banner = ''.join(c if c.isprintable() else ' ' for c in banner).strip()
                    return banner if banner else "[No valid banner text received]"

            except socket.timeout:
                # No immediate banner, maybe try sending a simple probe?
                # For simplicity, we'll skip sending probes in this version.
                # Example probe for HTTP: sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                # If sending probes, need another recv attempt here.
                 return "[No immediate banner (timeout)]"
            except Exception as recv_e:
                # print_status(f"[DBG] Recv error port {port}: {recv_e}") # Debug
                return f"[Error receiving banner: {recv_e}]"

        # If connect succeeded but recv didn't get anything meaningful immediately
        return "[Connected, but no banner received]"

    except socket.timeout:
        return "[Banner grab connection timeout]" # Shouldn't happen if scan already found it open
    except socket.error as e:
        # Handle connection refused, reset, etc. which might happen
        # if the port closed between the scan and the banner grab.
        return f"[Banner grab connection error: {e}]"
    except Exception as e:
         # Catch-all for unexpected errors during banner grab
         return f"[Unexpected banner grab error: {e}]"

# --- Scanning Logic (Phase 1: Port Discovery) ---
def scan_port(target_ip, port, timeout, verbose):
    """
    Attempts to connect to a single port.
    If open, adds the port to the global open_ports list.
    Logs closed/filtered status only if verbose is True.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                # Port is open - add to list for later processing
                with PRINT_LOCK:
                    # Try a quick service lookup here, but don't rely on it fully
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = "unknown" # Placeholder
                    open_ports.append({'port': port, 'service': service}) # Add as dict

                print_status(f"[+] Port {port:<5} is open ({service})")
            elif verbose:
                 print_status(f"[-] Port {port:<5} is closed/filtered")

    except socket.timeout:
        if verbose:
            print_status(f"[-] Port {port:<5} timed out (filtered?)")
    except socket.gaierror:
        print_status(f"[!] Error: Cannot resolve/reach {target_ip} during scan (Port {port})")
    except socket.error as e:
        if verbose:
            print_status(f"[!] Socket error on port {port}: {e}")

# --- Worker Thread (Runs Phase 1 tasks) ---
def worker(target_ip, timeout, verbose):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except Queue.Empty:
            break
        try:
            scan_port(target_ip, port, timeout, verbose)
        except Exception as e:
            print_status(f"[!] Unexpected error in worker scanning port {port}: {e}")
        finally:
            port_queue.task_done()

# --- Service/Banner Lookup (Phase 2) ---
def lookup_and_grab(target_ip, discovered_ports, grab_banners_flag, verbose):
    """
    Looks up standard services and optionally grabs banners for open ports.
    Updates the final_results dictionary.
    `discovered_ports` is a list of dictionaries like [{'port': p, 'service': s}, ...]
    """
    if not discovered_ports:
        return

    print_status("[*] Starting service refinement and banner grabbing phase...")
    socket.setdefaulttimeout(2.0) # Timeout for standard service lookup

    # Sort by port number
    discovered_ports.sort(key=lambda item: item['port'])

    for item in discovered_ports:
        port = item['port']
        service_name = item['service'] # Use the one found during scan first

        # Refine service name if it was 'unknown' or if lookup is desired anyway
        if service_name == "unknown":
            try:
                service_name = socket.getservbyport(port, "tcp")
            except OSError:
                service_name = "Unknown" # Confirmed unknown
            except socket.timeout:
                service_name = "Lookup Timeout"
            except Exception as e:
                 service_name = f"Lookup Error ({type(e).__name__})"
                 if verbose: print_status(f"[!] Service lookup error port {port}: {e}")

        banner = "[Not Requested]"
        if grab_banners_flag:
            # Add banner grabbing attempt
            if verbose: print_status(f"[*] Grabbing banner for port {port}...")
            banner = grab_banner(target_ip, port, BANNER_TIMEOUT)
            if verbose and banner.startswith("["): # Print errors/status from banner grab
                print_status(f"[*] Banner port {port}: {banner}")


        # Store final combined result
        with PRINT_LOCK: # Protect access to shared results dictionary
            final_results[port] = {'service': service_name, 'banner': banner}

    socket.setdefaulttimeout(None) # Reset global default
    print_status("[*] Service/Banner phase complete.")


# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description="Fast TCP Port Scanner with optional banner grabbing.",
        epilog="Example: scanner.py scanme.nmap.org -p 21-23,80,443 -t 100 -v -b"
        )
    parser.add_argument("target", help="Target IP address, hostname, or URL")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan (e.g., '1-1024', '80,443')")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Number of scan threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-w", "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Scan connection timeout (default: {DEFAULT_TIMEOUT}s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show resolution, closed ports, and banner grab details")
    parser.add_argument("-b", "--banner", action="store_true", help="Attempt to grab service banners for open ports") # New flag

    args = parser.parse_args()

    target_ip, original_target = resolve_target(args.target, args.verbose)
    if target_ip is None: sys.exit(1)

    ports_to_scan = parse_ports(args.ports)
    num_threads = args.threads
    scan_timeout = args.timeout # Use distinct name from banner timeout
    verbose = args.verbose
    grab_banners_flag = args.banner # Check if user requested banners

    if num_threads <= 0: print_status("[!] Threads must be positive."); sys.exit(1)
    if scan_timeout <= 0: print_status("[!] Timeout must be positive."); sys.exit(1)

    num_ports = len(ports_to_scan)
    if num_threads > num_ports:
        if verbose: print_status(f"[*] Reducing thread count from {num_threads} to {num_ports}")
        num_threads = num_ports

    print("-" * 60)
    print(f"Target:        {original_target}")
    if original_target != target_ip: print(f"Resolved IP:   {target_ip}")
    print(f"Ports:         {args.ports} ({num_ports} ports)")
    print(f"Scan Threads:  {num_threads}")
    print(f"Scan Timeout:  {scan_timeout}s")
    print(f"Grab Banners:  {'Enabled' if grab_banners_flag else 'Disabled'}")
    print(f"Verbose Mode:  {'Enabled' if verbose else 'Disabled'}")
    print(f"Started:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    start_time = time.monotonic()

    # --- Phase 1: Port Scanning ---
    print_status("[*] Starting port scanning phase...")
    for port in ports_to_scan: port_queue.put(port)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip, scan_timeout, verbose), daemon=True)
        threads.append(thread)
        thread.start()

    # Progress Indicator
    while not port_queue.empty():
         remaining = port_queue.qsize()
         processed = num_ports - remaining
         percent_done = (processed / num_ports) * 100 if num_ports > 0 else 100
         sys.stdout.write(f"\r[*] Scanning Progress: {processed}/{num_ports} ({percent_done:.1f}%) ")
         sys.stdout.flush()
         time.sleep(0.2)
    port_queue.join() # Wait for all scan tasks to finish
    sys.stdout.write("\r" + " " * 70 + "\r")
    sys.stdout.flush()
    print_status("[*] Port scanning phase complete.")
    scan_duration = time.monotonic() - start_time

    # --- Phase 2: Service/Banner Lookup ---
    # Make a copy of open_ports because lookup_and_grab modifies final_results
    discovered_ports_copy = list(open_ports)
    lookup_and_grab(target_ip, discovered_ports_copy, grab_banners_flag, verbose)

    end_time = time.monotonic()
    total_duration = end_time - start_time
    lookup_duration = total_duration - scan_duration

    # --- Results ---
    print("-" * 60)
    print(f"Scan Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan Duration: {scan_duration:.2f} seconds")
    print(f"Lookup/Banner: {lookup_duration:.2f} seconds")
    print(f"Total Duration: {total_duration:.2f} seconds")

    # Sort final results by port number for display
    sorted_ports = sorted(final_results.keys())

    if sorted_ports:
        print("\nOpen Ports, Services, and Banners:")
        for port in sorted_ports:
            result = final_results[port]
            service = result['service']
            banner = result['banner']
            # Format banner for cleaner multi-line display if needed
            # banner_display = ('\n' + ' ' * 14).join(banner.splitlines()) if '\n' in banner else banner
            banner_display = banner # Keep it simpler for now
            print(f"  Port {port:<5} ({service})")
            if grab_banners_flag:
                 # Only show banner line if requested, even if it failed
                 print(f"    Banner: {banner_display}")
    else:
        print("\nNo open ports found in the specified range.")

    print("-" * 60)


if __name__ == "__main__":
    print("="*60)
    print("!!! WARNING: Unauthorized scanning is illegal and unethical. !!!")
    print("!!!       Only scan hosts you have explicit permission.       !!!")
    print("="*60)
    try:
        main()
    except KeyboardInterrupt:
        print_status("\n[!] Scan interrupted by user.", flush=True)
        sys.exit(1)
    except Exception as e:
        print_status(f"\n[!!!] An unexpected critical error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)
