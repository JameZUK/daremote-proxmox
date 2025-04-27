#!/usr/bin/env python3

import argparse
import json
import getpass
import sys
import warnings
import socket
import re
import os
import stat  # For file permissions
from pathlib import Path  # For easier path handling
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException, AuthenticationError
# Optional: Disable insecure request warnings if verify_ssl=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import traceback # Import traceback module
# Removed unused imports

# Suppress InsecureRequestWarning if verify_ssl is False
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# --- Configuration ---
DEFAULT_CONFIG_DIR = Path.home() / ".config" / "proxmox_scanner"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
DEFAULT_OUTPUT_FILE = "proxmox_linux_guests.json"

LINUX_CT_OSTYPES = [
    "ubuntu", "debian", "centos", "fedora", "alpine",
    "archlinux", "gentoo", "opensuse", "rocky", "almalinux",
]
LINUX_VM_OSTYPES_HINTS = ["l26", "l24"] # Common Linux kernel hints in PVE
DEFAULT_SSH_PORT = "22"
DEFAULT_USERNAME = "root" # Placeholder for generated JSON, not PVE connection
DNS_TIMEOUT = 3 # Timeout in seconds for DNS lookups
API_TIMEOUT = 10 # Timeout for Proxmox API calls

# --- Global Variable for Password Handling ---
# Stores the last password that successfully authenticated during this run.
_last_successful_password = None

# --- Configuration File Functions ---

def load_config(config_path: Path):
    """Loads configuration from the specified JSON file path."""
    if config_path.exists():
        try:
            current_perms = stat.S_IMODE(os.stat(config_path).st_mode)
            # Check if group or other has read permissions
            if current_perms & (stat.S_IRGRP | stat.S_IROTH):
                print(f"Warning: Config file {config_path} has insecure permissions ({oct(current_perms)}). Attempting to restrict.", file=sys.stderr)
                try:
                    os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR) # Read/Write for User only
                    print(f"Permissions restricted to {oct(stat.S_IRUSR | stat.S_IWUSR)}.")
                except OSError as e:
                    print(f"Warning: Could not restrict permissions on {config_path}: {e}", file=sys.stderr)
            with open(config_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: Config file {config_path} is corrupted. Please fix or remove it.", file=sys.stderr)
            return {}
        except Exception as e:
            print(f"Error loading config file {config_path}: {e}", file=sys.stderr)
            return {}
    return {}

def save_config(config_data, config_path: Path):
    """Saves configuration to the specified JSON file path, ensuring directory and permissions."""
    try:
        config_dir = config_path.parent
        config_dir.mkdir(parents=True, exist_ok=True)
        # Write the file first
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        # Set permissions after writing
        os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR) # Read/Write for User only
        print(f"Configuration saved to {config_path}")
        print(f"Permissions set to {oct(stat.S_IRUSR | stat.S_IWUSR)}.")
    except Exception as e:
        print(f"Error saving config file {config_path}: {e}", file=sys.stderr)

# --- Proxmox Connection (Password Only - Tries Last Successful Password First) ---

def get_proxmox_connection(host_config, is_test_connection=False):
    """
    Establishes connection using username/password.
    Tries the last successful password first (if available) before prompting.
    host_config structure:
      {'host': 'addr', 'user': 'u@r', 'insecure': bool}
    is_test_connection: If True, only prompts, doesn't use/update the global cache.
    Returns connection object on success, None on failure.
    """
    global _last_successful_password # Declare intent to modify the global variable

    host = host_config['host']
    user = host_config.get('user') # e.g., root@pam
    verify_ssl = not host_config.get('insecure', False)
    px_api = None
    password_to_try = None
    prompted_password = None

    if not user:
        print(f"Error: Incomplete configuration for host {host}. Missing 'user'.", file=sys.stderr)
        print("Please re-add the host using --add-host.", file=sys.stderr)
        return None

    # --- Step 1: Try last successful password (only during normal scan) ---
    if not is_test_connection and _last_successful_password is not None:
        password_to_try = _last_successful_password
        print(f"DEBUG: Attempting password auth with last successful password for {user} on {host}")
        try:
            px_api = ProxmoxAPI(
                host, user=user, password=password_to_try,
                verify_ssl=verify_ssl, timeout=API_TIMEOUT
            )
            px_api.version.get() # Test connection
            print("DEBUG: Last successful password worked.")
            return px_api # Success with cached password
        except AuthenticationError:
            print("DEBUG: Last successful password failed. Will prompt.")
            # Don't return yet, fall through to prompt
        except ResourceException as re_exc:
            print(f"Error connecting to Proxmox host {host} with cached password: {re_exc} (Status: {re_exc.status_code})", file=sys.stderr)
            return None # Connection error other than auth
        except Exception as e:
            print(f"DEBUG: General connection exception with cached password: {repr(e)}")
            traceback.print_exc(limit=1, file=sys.stderr)
            print(f"General error connecting to Proxmox host {host} with cached password: {e}", file=sys.stderr)
            return None # Other connection error

    # --- Step 2: Prompt for password if needed ---
    # (Needed if it's a test connection, no password cached yet, or cached password failed auth)
    try:
        prompted_password = getpass.getpass(f"Enter password for {user} on {host}: ")
        if not prompted_password:
             print("Error: Password cannot be empty.", file=sys.stderr)
             return None
    except EOFError:
        print("\nInput aborted.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"\nError getting password: {e}", file=sys.stderr)
        return None

    # --- Step 3: Try connection with prompted password ---
    password_to_try = prompted_password
    print(f"DEBUG: Attempting password auth with prompted password for {user} on {host}")
    try:
        px_api = ProxmoxAPI(
            host, user=user, password=password_to_try,
            verify_ssl=verify_ssl, timeout=API_TIMEOUT
        )
        px_api.version.get() # Test connection
        print("DEBUG: Prompted password connection successful.")
        # Update the global cache only if successful and not a test connection
        if not is_test_connection:
            _last_successful_password = password_to_try
            print("DEBUG: Updated last successful password.")
        return px_api
    except AuthenticationError as auth_e:
        print(f"Authentication failed for {user} on {host} with prompted password: {auth_e}", file=sys.stderr)
        return None # Auth failed
    except ResourceException as re_exc:
        print(f"Error connecting to Proxmox host {host} with prompted password: {re_exc} (Status: {re_exc.status_code})", file=sys.stderr)
        return None # Connection error other than auth
    except Exception as e:
        print(f"DEBUG: General connection exception with prompted password: {repr(e)}")
        traceback.print_exc(limit=1, file=sys.stderr)
        print(f"General error connecting to Proxmox host {host} with prompted password: {e}", file=sys.stderr)
        return None # Other connection error


# --- Guest Scanning Functions ---
# (No changes needed in these functions)
def try_reverse_lookup(ip_address):
    """Attempts reverse DNS lookup, returns FQDN or None."""
    if not ip_address: return None
    try:
        print(f" Trying reverse DNS for {ip_address}...", end="")
        socket.setdefaulttimeout(DNS_TIMEOUT)
        fqdn, aliaslist, ipaddrlist = socket.gethostbyaddr(ip_address)
        socket.setdefaulttimeout(None); print(f" Success: {fqdn}."); return fqdn
    except (socket.herror, socket.gaierror, socket.timeout) as dns_e:
        socket.setdefaulttimeout(None); print(f" Failed ({type(dns_e).__name__})."); return None
    except Exception as sock_e:
        socket.setdefaulttimeout(None); print(f" Error ({type(sock_e).__name__})."); return None

def try_forward_lookup(hostname):
    """Attempts forward DNS lookup, returns first IP address or None."""
    if not hostname: return None
    try:
        print(f" Trying forward DNS for {hostname}...", end="")
        socket.setdefaulttimeout(DNS_TIMEOUT)
        # Use getaddrinfo for IPv4/IPv6 compatibility
        addr_info = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC) # AF_UNSPEC allows both IPv4 and IPv6
        socket.setdefaulttimeout(None)
        if addr_info:
            # Prefer IPv4 if available, otherwise take the first address
            ipv4s = [info[4][0] for info in addr_info if info[0] == socket.AF_INET]
            ipv6s = [info[4][0] for info in addr_info if info[0] == socket.AF_INET6]
            ip_address = ipv4s[0] if ipv4s else (ipv6s[0] if ipv6s else None)

            if ip_address:
                print(f" Success: {ip_address}."); return ip_address
            else:
                 print(" No suitable address found."); return None # Should not happen if addr_info is populated
        else: print(" No address found."); return None
    except (socket.herror, socket.gaierror, socket.timeout) as dns_e:
        socket.setdefaulttimeout(None); print(f" Failed ({type(dns_e).__name__})."); return None
    except Exception as sock_e:
        socket.setdefaulttimeout(None); print(f" Error ({type(sock_e).__name__})."); return None


def get_address_via_api(px_conn, node_name, vmid, guest_type):
    """Attempts to get IP address via Agent (VM) or Config (CT)."""
    ip_address = None
    print(f"      Attempting API IP detection ({guest_type} {vmid})...", end="")
    try:
        if guest_type == "VM":
            try:
                vm_status = px_conn.nodes(node_name).qemu(vmid).status.current.get()
                if vm_status.get('agent') == 1 and vm_status.get('status') == 'running':
                    # Temporarily increase timeout for agent call
                    px_conn.nodes(node_name).qemu(vmid).agent.set_options(timeout=15)
                    interfaces = px_conn.nodes(node_name).qemu(vmid).agent.get('network-get-interfaces')
                    # Reset timeout (consider storing original and restoring if needed)
                    px_conn.nodes(node_name).qemu(vmid).agent.set_options(timeout=API_TIMEOUT) # Reset to default API timeout

                    if interfaces and 'result' in interfaces:
                        ipv4s, ipv6s = [], []
                        for iface in interfaces['result']:
                            # Skip loopback interfaces
                            if iface.get('name', '').lower() == 'lo':
                                continue
                            if 'ip-addresses' in iface:
                                for ip_info in iface['ip-addresses']:
                                    ip = ip_info.get('ip-address')
                                    ip_type = ip_info.get('ip-address-type')
                                    # Filter out loopback, link-local, and unspecified addresses more robustly
                                    if ip and not ip.startswith('127.') and not ip.startswith('fe80:') and not ip == '::1' and not ip.startswith('169.254.'):
                                        if ip_type == 'ipv4': ipv4s.append(ip)
                                        elif ip_type == 'ipv6': ipv6s.append(ip) # Only add if explicitly IPv6 type
                        # Prioritize IPv4, then IPv6
                        ip_address = ipv4s[0] if ipv4s else (ipv6s[0] if ipv6s else None)
                        print(f" Agent found {ip_address}." if ip_address else " Agent found no suitable IPs.", end="")
                    else: print(" Agent returned no interfaces.", end="")
                else: print(" Agent not running/VM stopped.", end="")
            except ResourceException as re:
                # Reset timeout in case of exception during agent call
                try: px_conn.nodes(node_name).qemu(vmid).agent.set_options(timeout=API_TIMEOUT)
                except: pass # Ignore errors resetting timeout after another error
                if "command 'network-get-interfaces' failed" in str(re): print(" Agent call failed.", end="")
                elif "No QEMU guest agent configured" in str(re): print(" Agent not configured.", end="")
                elif re.status_code == 500 and "guest agent not running" in str(re).lower(): print(" Agent not running.", end="")
                else: print(f" Agent error {re.status_code}.", end="")
            except Exception as agent_e:
                 # Reset timeout in case of exception
                try: px_conn.nodes(node_name).qemu(vmid).agent.set_options(timeout=API_TIMEOUT)
                except: pass
                print(f" Agent Exception: {type(agent_e).__name__}.", end="")
        elif guest_type == "CT":
            try:
                ct_config = px_conn.nodes(node_name).lxc(vmid).config.get()
                found_ips = []
                # Iterate through network interfaces (net0, net1, etc.)
                for key, value in ct_config.items():
                    if key.startswith("net") and isinstance(value, str):
                        # Extract IPv4 static address (ignore dhcp)
                        ip4_match = re.search(r'ip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:/\d+)?', value, re.IGNORECASE)
                        # Extract IPv6 static address (ignore dhcp/auto)
                        ip6_match = re.search(r'ip6=([0-9a-fA-F:]+)(?:/\d+)?', value, re.IGNORECASE)

                        ip = None
                        # Prioritize IPv4
                        if ip4_match and ip4_match.group(1).lower() != 'dhcp':
                            ip = ip4_match.group(1)
                        elif ip6_match and ip6_match.group(1).lower() not in ['dhcp', 'auto']:
                            ip = ip6_match.group(1)

                        # Filter out loopback, link-local etc.
                        if ip and not ip.startswith('127.') and not ip.startswith('fe80:') and not ip == '::1' and not ip.startswith('169.254.'):
                            found_ips.append(ip)

                # Select the first valid IP found (could be refined)
                ip_address = found_ips[0] if found_ips else None
                print(f" Config found {ip_address}." if ip_address else " Config has no suitable static IPs.", end="")
            except Exception as conf_e: print(f" Config Error: {conf_e}.", end="")
        print("") # Newline after attempt message
        return ip_address
    except Exception as e:
        print(f"\n      Error during API IP detection for {vmid}: {e}")
        # traceback.print_exc() # Can be noisy, enable if needed for debugging this part
        return None

def create_guest_entry(px_conn, node_name, guest_info, guest_type, proxmox_host):
    """Creates JSON entry, performing lookups for 'address' field."""
    vmid = guest_info.get("vmid")
    guest_name = guest_info.get("name", f"guest-{vmid}")
    address_final = guest_name # Default to guest name
    ip_used_for_lookup = None # Track which IP led to FQDN

    # --- Determine Address: FQDN (from API IP) > API IP > FQDN (from Forward DNS IP) > Forward DNS IP > Name ---
    print(f"      Step 1: Attempting API IP for {guest_name} ({vmid})...")
    ip_from_api = get_address_via_api(px_conn, node_name, vmid, guest_type)

    if ip_from_api:
        print(f"      Step 2: API yielded IP {ip_from_api}. Trying reverse DNS...")
        fqdn_from_api_ip = try_reverse_lookup(ip_from_api)
        if fqdn_from_api_ip:
            print(f"      Step 2a: Reverse DNS successful. Using FQDN: {fqdn_from_api_ip}")
            address_final = fqdn_from_api_ip
            ip_used_for_lookup = ip_from_api # Record the IP that resolved
        else:
            print(f"      Step 2b: Reverse DNS failed. Using API IP: {ip_from_api}")
            address_final = ip_from_api
    else:
        print(f"      Step 3: API yielded no suitable IP. Trying forward DNS for guest name '{guest_name}'...")
        ip_from_forward_dns = try_forward_lookup(guest_name)
        if ip_from_forward_dns:
            print(f"      Step 4: Forward DNS yielded IP {ip_from_forward_dns}. Trying reverse DNS...")
            fqdn_from_forward_ip = try_reverse_lookup(ip_from_forward_dns)
            if fqdn_from_forward_ip:
                print(f"      Step 4a: Reverse DNS successful. Using FQDN: {fqdn_from_forward_ip}")
                address_final = fqdn_from_forward_ip
                ip_used_for_lookup = ip_from_forward_dns # Record the IP that resolved
            else:
                print(f"      Step 4b: Reverse DNS failed. Using Forward DNS IP: {ip_from_forward_dns}")
                address_final = ip_from_forward_dns
        else:
            print(f"      Step 5: Forward DNS failed. Using guest name as address: {guest_name}")
            address_final = guest_name # Stick with guest name

    # --- Determine OS Type ---
    os_type = "Linux" # Default
    config_ostype = guest_info.get("ostype", "").lower()
    if guest_type == "CT" and config_ostype in LINUX_CT_OSTYPES:
        # Use the specific type for known Linux CTs
        os_type = config_ostype.capitalize()
    elif guest_type == "VM" and config_ostype in LINUX_VM_OSTYPES_HINTS:
        # Keep generic for VMs based on hint, could be refined with agent info later
        os_type = "Linux"
    # Add logic here if you want to attempt OS detection via agent for VMs

    # --- Collect Tags ---
    tags = ["Proxmox", guest_type, proxmox_host, node_name]
    tag_str = guest_info.get("tags")
    if isinstance(tag_str, str) and tag_str.strip():
        # Split tags by semicolon or space, remove duplicates and empty strings
        parsed_tags = [t.strip() for t in re.split(r'[;\s]+', tag_str) if t.strip()]
        tags.extend(parsed_tags)

    # --- Construct Final JSON Entry ---
    # This structure seems tailored for a specific application (like Termius?)
    entry = {
        "label": f"{guest_name} ({vmid} on {node_name})",
        "address": address_final, # Result from multi-step lookup
        "port": DEFAULT_SSH_PORT,
        "username": DEFAULT_USERNAME, # Placeholder - user needs to configure this
        "usePassword": 0, # Default to key-based auth assumption
        "password": "PASTE_PRIVATE_KEY_HERE_IF_NEEDED", # Placeholder (or empty string)
        "publicKey": "", # Placeholder
        "phrase": "", # Placeholder for key passphrase
        "visible": 1,
        "osType": os_type,
        "containerName": "", # Not applicable unless osType is Docker (handled elsewhere)
        "tags": sorted(list(set(tags))), # Ensure unique tags and sort alphabetically
        "othercode": "SUDO_PASSWORD_PLACEHOLDER", # Placeholder for sudo password if needed by target app
        "settings": {
            # These seem specific to the target application consuming the JSON
            "biometric2Sudo": 0,
            "dockerNeedsSudo": 0,
            "smartNeedSudo": 0,
            "useFishShell": 0,
            "addrtypeused": 0, # 0 for any IP type (IPv4/IPv6)
            "sudoPromptWords": "[sudo] password for", # Common default sudo prompt
            "smartctlPath": "" # Default (use PATH)
        },
        # Add extra metadata gathered during scan (optional)
        "_scan_metadata": {
            "proxmox_host": proxmox_host,
            "node": node_name,
            "vmid": vmid,
            "guest_type": guest_type,
            "detected_ip_api": ip_from_api,
            "detected_ip_dns": ip_from_forward_dns if not ip_from_api else None,
            "ip_used_for_fqdn": ip_used_for_lookup,
            "pve_guest_name": guest_name,
            "pve_ostype": config_ostype,
            "pve_tags": tag_str
        }
    }
    return entry

# --- Main Execution Logic ---
def main():
    default_config_path_str = str(DEFAULT_CONFIG_FILE)
    parser = argparse.ArgumentParser(
        description="Scan Proxmox hosts for Linux guests using stored config or add new hosts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Workflow:
1. Add each Proxmox host ONCE using --add-host:
   {sys.argv[0]} --add-host pve1.example.com [--insecure]
   (Prompts for Username (user@realm) and Password. Stores username only.)

2. Run subsequent scans with no arguments:
   {sys.argv[0]} [-o output.json] [-c config.json]
   (Connects using the username stored in the config file.)
   (Tries the last successful password first, then prompts if needed.)

Default configuration file: {default_config_path_str}
Default output file: {DEFAULT_OUTPUT_FILE}
""")
    # --- Arguments for adding host ---
    parser.add_argument("--add-host", metavar="HOSTNAME_OR_IP", help="Add or update configuration for a Proxmox host (uses password auth).")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification when adding/testing the host.")
    # --- Arguments for scanning ---
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_FILE, help=f"Output JSON file name for guest list (Default: {DEFAULT_OUTPUT_FILE}).")
    parser.add_argument("-c", "--config", default=default_config_path_str, help=f"Path to the configuration file (Default: {default_config_path_str}).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (shows detailed steps).")


    args = parser.parse_args()
    config_file_path = Path(args.config).resolve()
    config = load_config(config_file_path)
    verbose = args.verbose

    # Simple function to print only if verbose is enabled
    def print_verbose(*print_args, **print_kwargs):
        if verbose:
            print(*print_args, **print_kwargs)

    # --- Mode 1: Add or Update Host Configuration (Password Only) ---
    if args.add_host:
        host = args.add_host
        insecure = args.insecure
        # Config entry will only store user and insecure flag
        host_config_entry = {"insecure": insecure}

        print(f"\nConfiguring host: {host} (Password Authentication)")

        px_conn = None
        username = ""
        # We only need the password temporarily for the test connection
        # password = "" # No need to declare here

        # Prompt for Username
        while not username:
            try: username = input(f"Enter the Username (e.g., user@realm): ").strip()
            except EOFError: print("\nInput aborted.", file=sys.stderr); sys.exit(1)
            if not username: print("Username cannot be empty.", file=sys.stderr)
            elif '@' not in username: print("Username should include the realm (e.g., user@pam).", file=sys.stderr); username=""

        # Prepare config for testing
        test_config = {
            'host': host,
            'user': username,
            'insecure': insecure
        }

        print("\nTesting connection (will prompt for password)...")
        # Call get_proxmox_connection with is_test_connection=True
        # This ensures it prompts without using/updating the global cache
        px_conn = get_proxmox_connection(test_config, is_test_connection=True)

        # --- Save Configuration if Connection Test Succeeded ---
        if px_conn:
            print("Connection test successful!")
            # Populate final config entry for saving (DO NOT SAVE PASSWORD)
            host_config_entry["user"] = username
            config[host] = host_config_entry # Add/update the entry for this host
            save_config(config, config_file_path)
            print(f"Configuration for host '{host}' saved successfully.")
        else:
            print("Connection test failed. Please verify username, password, and host accessibility.", file=sys.stderr)
            sys.exit(1) # Exit if test connection failed

        print("\nHost configuration complete. Run the script without --add-host to perform a scan.")
        sys.exit(0)


    # --- Mode 2: Normal Run (Scan Guests using Config - Password Only) ---
    if not config:
        print(f"Error: Configuration file '{config_file_path}' is empty or not found.", file=sys.stderr)
        print(f"Please run with '--add-host HOSTNAME' to configure at least one Proxmox server.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting scan using configuration from {config_file_path}...")
    all_linux_guests = []
    connection_errors = 0
    failed_hosts = []

    for host, host_conf in config.items():
        print("-" * 20)
        print(f"Processing Proxmox host: {host}")

        # Prepare config dict for the connection function
        current_host_conf = host_conf.copy()
        current_host_conf['host'] = host # Ensure host key is present

        # Use the get_proxmox_connection which now tries last successful password first
        px_conn = get_proxmox_connection(current_host_conf) # is_test_connection defaults to False

        if not px_conn:
            print(f"Skipping host {host} due to connection/authentication error.")
            connection_errors += 1
            failed_hosts.append(host)
            continue

        # --- Scan Nodes and Guests (No changes below this point in the loop) ---
        try:
            nodes = px_conn.nodes.get()
            for node in nodes:
                node_name = node['node']
                print(f"  Scanning node: {node_name}")

                # Process Containers (LXC)
                try:
                    print_verbose(f"    Fetching containers on node {node_name}...")
                    containers = px_conn.nodes(node_name).lxc.get()
                    print_verbose(f"    Found {len(containers)} container(s).")
                    for ct in containers:
                        ct_ostype = ct.get("ostype", "").lower()
                        ct_name = ct.get('name', f"ct-{ct.get('vmid')}")
                        ct_vmid = ct.get('vmid')
                        print_verbose(f"      Checking CT: {ct_name} ({ct_vmid}), OS Type: '{ct_ostype}'")
                        if ct_ostype in LINUX_CT_OSTYPES:
                            print(f"    Processing Linux CT: {ct_name} ({ct_vmid})...")
                            guest_entry = create_guest_entry(px_conn, node_name, ct, "CT", host)
                            all_linux_guests.append(guest_entry)
                        else:
                            print_verbose(f"      Skipping CT {ct_name} ({ct_vmid}): OS type '{ct_ostype}' not in Linux list.")
                except Exception as e:
                    print(f"    Error fetching/processing containers on node {node_name}: {e}", file=sys.stderr)
                    traceback.print_exc(limit=1, file=sys.stderr) # Print limited traceback

                # Process Virtual Machines (QEMU)
                try:
                    print_verbose(f"    Fetching VMs on node {node_name}...")
                    vms = px_conn.nodes(node_name).qemu.get()
                    print_verbose(f"    Found {len(vms)} VM(s).")
                    for vm in vms:
                        vm_name = vm.get('name', f"vm-{vm.get('vmid')}")
                        vm_vmid = vm.get('vmid')
                        print_verbose(f"      Checking VM: {vm_name} ({vm_vmid})")
                        try:
                            # Get config to check ostype hint
                            vm_config = px_conn.nodes(node_name).qemu(vm_vmid).config.get()
                            vm_ostype_hint = vm_config.get("ostype", "").lower()
                            print_verbose(f"      VM {vm_name} ({vm_vmid}) OS Type Hint: '{vm_ostype_hint}'")
                            # Check if the hint suggests Linux
                            if vm_ostype_hint in LINUX_VM_OSTYPES_HINTS:
                                print(f"    Processing potential Linux VM: {vm_name} ({vm_vmid})...")
                                guest_entry = create_guest_entry(px_conn, node_name, vm, "VM", host)
                                all_linux_guests.append(guest_entry)
                            else:
                                print_verbose(f"      Skipping VM {vm_name} ({vm_vmid}): OS hint '{vm_ostype_hint}' not in Linux list.")
                        except ResourceException as cfg_e:
                            # Handle case where VM config might not be accessible (e.g., locked)
                            if cfg_e.status_code == 500 and 'locked' in str(cfg_e).lower():
                                print(f"      VM {vm_name} ({vm_vmid}) is locked. Skipping config check.", file=sys.stderr)
                            else:
                                print(f"      Could not get config for VM {vm_name} ({vm_vmid}): {cfg_e}. Skipping.", file=sys.stderr)
                        except Exception as vm_proc_e:
                            print(f"      Error processing VM {vm_name} ({vm_vmid}): {vm_proc_e}. Skipping.", file=sys.stderr)
                            traceback.print_exc(limit=1, file=sys.stderr) # Print limited traceback
                except Exception as e:
                    print(f"    Error fetching/processing VMs on node {node_name}: {e}", file=sys.stderr)
                    traceback.print_exc(limit=1, file=sys.stderr) # Print limited traceback
        except Exception as e:
            print(f"Error processing nodes/guests on host {host}: {e}", file=sys.stderr)
            traceback.print_exc(limit=1, file=sys.stderr) # Print limited traceback

    # --- Write output JSON ---
    print("-" * 20)
    if connection_errors > 0:
        print(f"Warning: Failed to connect to {connection_errors} host(s): {', '.join(failed_hosts)}", file=sys.stderr)

    if all_linux_guests:
        print(f"Scan complete. Found {len(all_linux_guests)} potential Linux guests across reachable hosts.")
        try:
            # Sort by label for consistent output
            all_linux_guests.sort(key=lambda x: x['label'])
            output_path = Path(args.output).resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True) # Ensure output directory exists
            with open(output_path, 'w') as f:
                json.dump(all_linux_guests, f, indent=2)
            print(f"Successfully wrote guest entries to {output_path}")
            print("\nNOTE: Please review the generated file, especially placeholder fields like 'username', 'password', 'publicKey', 'othercode'.")
            print("Address determination order: FQDN (Reverse DNS on API IP) > API IP > FQDN (Reverse DNS on Forward DNS IP) > Forward DNS IP > Guest Name.")
        except IOError as e:
            print(f"Error writing output file {output_path}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"An unexpected error occurred during output generation: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
    else:
        print(f"Scan complete. No Linux guests found matching the criteria across reachable hosts.")


if __name__ == "__main__":
    main()
