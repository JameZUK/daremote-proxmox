# NAME

**proxmox-daremote** - Scan Proxmox hosts for Linux guests and generate a JSON inventory.

# SYNOPSIS

**proxmox-daremote** --add-host *HOSTNAME_OR_IP* [--insecure] [-c *CONFIG_FILE*]

**proxmox-daremote** [-o *OUTPUT_FILE*] [-c *CONFIG_FILE*] [-v]

# DESCRIPTION

**proxmox-daremote** connects to one or more Proxmox VE hosts using stored user credentials, scans for running Linux Containers (LXC) and Virtual Machines (QEMU/KVM), attempts to determine a usable network address (FQDN or IP) for each guest, and outputs the results as a JSON file.

The script uses password-based authentication. It securely prompts for the password when adding a host configuration and during scans. To minimize repeated prompts during a scan, it will first try the password that successfully authenticated against the *previous* host in the same run before prompting again if that fails.

The generated JSON output is structured for potential use with SSH clients or inventory management tools (e.g., Termius), containing fields like label, address, port, OS type, and tags.

# OPTIONS

* `--add-host HOSTNAME_OR_IP`  
    Adds or updates the configuration for the specified Proxmox host. The script will prompt for the username (in `user@realm` format, e.g., `root@pam`) and the corresponding password. It performs a connection test before saving the configuration. Only the username and the insecure flag are stored; the password is **not** saved in the configuration file.

* `--insecure`  
    Disables SSL certificate verification when connecting to the Proxmox host. Use this if your Proxmox host uses self-signed certificates. Applies during both `--add-host` and normal scans.

* `-o OUTPUT_FILE`, `--output OUTPUT_FILE`  
    Specifies the path for the output JSON file containing the list of discovered Linux guests.  
    (Default: `proxmox_linux_guests.json` in the current directory)

* `-c CONFIG_FILE`, `--config CONFIG_FILE`  
    Specifies the path to the JSON configuration file storing host connection details (usernames and insecure flags).  
    (Default: `~/.config/proxmox_scanner/config.json`)

* `-v`, `--verbose`  
    Enables verbose output, showing more detailed steps during the scan (e.g., guest checking, API calls).

* `-h`, `--help`  
    Shows the help message and exits.

# CONFIGURATION

The script uses a JSON configuration file to store connection details for each Proxmox host. By default, this file is located at `~/.config/proxmox_scanner/config.json`.

Each key in the JSON object is the hostname or IP address of a Proxmox host. The value is an object containing:

* `user`: The username used for authentication (e.g., `root@pam`).  
* `insecure`: A boolean (`true` or `false`) indicating whether to disable SSL verification for this host.

**Example `config.json`:**

```json  
{  
  "pve1.example.com": {  
    "insecure": false,  
    "user": "root@pam"  
  },  
  "192.168.1.100": {  
    "insecure": true,  
    "user": "scanner@pve"  
  }  
}
```

The script attempts to set secure permissions (read/write for user only) on the configuration file upon loading and saving.  
**Note:** Passwords are **never** stored in the configuration file.

# **WORKFLOW**

1. **Add Hosts:** For each Proxmox host you want to scan, run the script with the \--add-host option:  
   proxmox-daremote \--add-host pve1.example.com

   or, if using self-signed certificates:  
   proxmox-daremote \--add-host 192.168.1.100 \--insecure

   You will be prompted for the username (e.g., root@pam) and password for that host. The script will test the connection and save the username to the configuration file if successful. Repeat for all hosts.  
2. **Scan Hosts:** To perform a scan using the saved configuration, run the script without \--add-host:  
   proxmox-daremote

   or specify a custom output file:  
   proxmox-daremote \-o my\_inventory.json

   The script will iterate through the hosts in the configuration file. For each host, it will attempt to authenticate. It will first try the password that worked for the previous host (if any). If that fails, it will prompt you for the password for the current host's configured user. Once connected, it scans the nodes for Linux guests.

# **OUTPUT**

The script generates a JSON file (default: proxmox\_linux\_guests.json) containing a list of objects, where each object represents a discovered Linux guest.  
**Key fields in each guest object:**

* label: A descriptive label (e.g., webserver (101 on pve-node1)).  
* address: The determined network address for the guest. The script attempts discovery in this order:  
  1. FQDN via reverse DNS lookup of IP found via Proxmox API (QEMU Agent/LXC Config).  
  2. IP found via Proxmox API.  
  3. FQDN via reverse DNS lookup of IP found via forward DNS lookup of guest name.  
  4. IP found via forward DNS lookup of guest name.  
  5. Proxmox guest name (as a fallback).  
* port: Default SSH port (22).  
* username: Default username (root). **Placeholder \- Needs manual review/update.**  
* osType: Detected OS type (e.g., Ubuntu, Debian, Linux).  
* tags: A list of tags, including Proxmox, guest type (VM/CT), Proxmox host, node name, and any tags assigned within Proxmox.  
* \_scan\_metadata: An internal object containing details gathered during the scan (host, node, vmid, detected IPs, etc.).  
* Other fields (usePassword, password, publicKey, phrase, visible, containerName, othercode, settings): These are often placeholders tailored for specific SSH clients like Termius and likely require manual adjustment after generation.

# **AUTHENTICATION**

This script uses **username and password** authentication only.

* During \--add-host, you provide the username and password to test the connection. Only the username is saved.  
* During a normal scan, the script retrieves the username from the config file.  
  * It first tries the password that successfully authenticated against the *most recent previous host* in the current script run.  
  * If that password fails authentication for the current host, or if it's the first host being processed, the script securely prompts for the password for the configured username using getpass.  
  * If a prompted password works, it becomes the "last successful password" to be tried on the *next* host in the list.

# **DEPENDENCIES**

* Python 3.x  
* proxmoxer: Python library for the Proxmox VE API. (pip install proxmoxer)  
* requests: (Though potentially installed as a dependency of proxmoxer).

# **FILES**

* \~/.config/proxmox\_scanner/config.json  
  Default path for the configuration file storing host details (username, insecure flag).

# **EXAMPLES**

1. **Add a host with standard SSL:**  
   ./proxmox-daremote \--add-host pve.mydomain.local

   *(Prompts for user@realm and password)*  
2. **Add a host with a self-signed certificate:**  
   ./proxmox-daremote \--add-host 10.0.0.5 \--insecure

   *(Prompts for user@realm and password)*  
3. **Run** a scan using the default config **and output files:**  
   ./proxmox-daremote

   *(Prompts for password(s) as needed)*  
4. **Run a scan with verbose output and a custom output file:**  
   ./proxmox-daremote \-v \-o /path/to/inventory.json \-c /path/to/my\_config.json

   *(Prompts for password(s) as needed)*

# **NOTES**

* **Security:** Passwords are never stored in the configuration file. They are handled in memory only during the script's execution and requested via secure prompts (getpass). However, ensure the machine running the script is secure.  
* **Permissions:** The user account used for authentication needs sufficient permissions within Proxmox to view nodes, list VMs/CTs, read their configurations, and potentially interact with the QEMU guest agent (e.g., PVEAuditor role might suffice for basic listing, but VM.Audit or higher might be needed for agent interaction).  
* **QEMU Guest Agent:** IP address detection for VMs relies heavily on the QEMU Guest Agent being installed, running, and configured within the guest OS. If the agent is not available, the script falls back to DNS lookups based on the VM name.  
* **DNS Resolution:** The accuracy of FQDNs depends on correct forward and reverse DNS configuration in your network environment.

# **AUTHOR**

*(Add author information here)*

# **BUGS**

\*(Add bug reporting information here, e.g., GitHub Issues
