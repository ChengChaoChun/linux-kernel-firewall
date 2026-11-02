# Linux Kernel Module Firewall
A simple IPv4 firewall implemented as a Linux Kernel Module using Netfilter.

The firewall allows users to dynamically add, remove, and list blocked IP addresses through a `/proc/firewall` interface.

## Architecture
This project uses the Netfilter framework to intercept incoming IPv4 packets and check whether their source IP address exists in the blocked IP list.

The Hook is registered at:

- Protocol Family: `NFPROTO_IPV4`
- Hook Point: `NF_INET_LOCAL_IN`
- Priority: `NF_IP_PRI_FIRST`

`NF_INET_LOCAL_IN` handles incoming packets destined for the local machine. Therefore, this firewall filters packets received by the local host and does not filter forwarded packets passing through the machine.

### Packet Filtering Flow
```text
Incoming IPv4 Packet
        |
        v
  Netfilter Hook (NF_INET_LOCAL_IN)
        |
        v
  Extract Source IP
        |
        v
  Search Blocked IP List
        |
        +------------------+
        |                  |
        v                  v
   IP Matched          No Match
        |                  |
        v                  v
    NF_DROP             NF_ACCEPT
```

## Project Structure
```text
.
├── firewall_main.c   # Kernel module and Netfilter firewall
├── firewallctl.c     # Userspace firewall management utility
└── Makefile          # Build configuration
```

## Requirements
- Linux
- GCC
- Make

## Build
Compile the kernel module and userspace utility:

```bash
make
```

This generates:
- `firewall_main.ko` - Linux Kernel Module
- `firewallctl` - Userspace management utility

## Run

### 1. Load the Kernel Module
```bash
sudo insmod firewall_main.ko
```

Check kernel logs:
```bash
sudo dmesg 
```

### 2. Add a Blocked IP
```bash
sudo ./firewallctl add <IPv4>
```

### 3. List Blocked IPs
```bash
sudo ./firewallctl list
```

### 4. Remove a Blocked IP
```bash
sudo ./firewallctl del <IPv4>  
```

### 5. Unload the Kernel Module
```bash
sudo rmmod firewall_main
```

## Clean
Remove generated build files:

```bash
make clean
```