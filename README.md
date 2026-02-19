# erspan_tc

An eBPF-based Traffic Control (TC) filter designed to decapsulate ERSPAN Type II traffic and redirect the inner frames to a target interface.

## Requirements

### Build Dependencies
* make
* clang
* libbpf-devel

### Runtime Dependencies
* iproute2
* bpftool
* jq (required for Makefile automation)
* python3-scapy (optional, for testing)

---

## Makefile Targets

| Target | Description |
| :--- | :--- |
| make debug | Compiles the BPF object with the DEBUG flag enabled. |
| make release | Compiles a clean version without debug symbols/output. |
| make load | Attaches the filter to DEV at DIR. |
| make unload | Detaches the filter and removes the clsact qdisc. |
| make reload | Performs unload, recompiles, and loads the filter again. |
| make set_config | Sets redirect target and Session ID. Usage: make set_config ID=100 TARGET_DEV=dummy0. |
| make get_config | Displays current configuration from the erspan_cfg_map. |
| make get_stats | Displays decapsulation statistics per CPU from erspan_stat_map. |
| make trace | Streams bpf_printk() output from the kernel trace pipe. |
| make clean | Removes compiled object files. |

---

## Setup Examples

### 1. Basic Setup (No Redirect)
In this scenario, the filter decapsulates packets and passes them back to the networking stack on the same interface.

# Create veth-pairs
ip link add veth2 type veth peer name aci
ip link add span type veth peer name veth2_mirror

# Configure MTU for Jumbo Frames
for dev in veth2 aci span veth2_mirror; do ip link set $dev mtu 9000; done

# Enable Promiscuous mode
ip link set span promisc on
ip link set veth2_mirror promisc on

# Bring interfaces up
ip link set veth2 up && ip link set aci up
ip link set span up && ip link set veth2_mirror up

# Mirror veth2 ingress to veth2_mirror
tc qdisc add dev veth2 handle ffff: ingress
tc filter add dev veth2 ingress matchall action mirred egress mirror dev veth2_mirror

# Load the BPF filter
make load DEV=veth2_mirror DIR=egress

### 2. Redirect Setup (Advanced)
Decapsulates ERSPAN traffic and redirects the inner payload to a dummy interface for further analysis (e.g., via tcpdump).

# Create interfaces
ip link add veth2 type veth peer name aci
ip link add span type dummy

# Configure MTU
for dev in veth2 aci span; do ip link set $dev mtu 9000; done

# Set IP on endpoint and bring up
ip addr add 10.10.3.150/24 dev veth2
ip link set veth2 up && ip link set aci up && ip link set span up

# Load filter on ingress
make load DEV=veth2 DIR=ingress

# Configure Session-ID filtering and redirect target
make set_config ID=100 TARGET_DEV=span

---

## Testing with Scapy

To verify that the eBPF program correctly handles GRE optional fields (like Checksums), you can use the following Scapy script. This script generates a GRE-encapsulated ERSPAN packet with a valid checksum.

### Test Script (send_test_packet.py)
from scapy.all import Ether, IP, GRE, sendp

# Configure parameters
IFACE = "aci" # Send into the veth pair
SESSION_ID = 100

# Build packet: Outer Eth / Outer IP / GRE (with Checksum) / ERSPAN Dummy / Inner Eth / Inner IP
# GRE(chksum_present=1) sets the 0x8000 flag and triggers automatic checksum calculation.
pkt = (Ether(dst="aa:bb:cc:dd:ee:ff") / 
       IP(dst="10.10.3.150") / 
       GRE(chksum_present=1, proto=0x88be) / 
       b'\x10\x00\x00\x64\x00\x00\x00\x00' /  # ERSPAN Type II (Ver 1, ID 100)
       Ether() / IP() )

print(f"Sending ERSPAN packet with GRE Checksum (Session ID: {SESSION_ID})...")
sendp(pkt, iface=IFACE, verbose=False)

---

## Monitoring & Debugging

### Trace Pipe
To see real-time log output from the BPF program (only available in debug build):
make trace

### Statistics
To monitor decapsulation performance and errors:
make get_stats

The statistics are stored in a PERCPU_ARRAY. This ensures high performance on multi-core systems by providing lockless counters for each CPU.

### Configuration
Verify the current map state:
make get_config

---

## Technical Details

### Header Parsing & GRE Options
The program dynamically parses the GRE header to account for optional fields. It checks the GRE flags to determine the presence of Checksums (0x8000), Keys (0x2000), or Sequence Numbers (0x1000) and adjusts the pointer to the ERSPAN header accordingly.

### ERSPAN Specification
The decapsulator targets ERSPAN Type II. It validates that the version field is set to 1 (RFC 8892).

### Decapsulation Logic
* Preservation of Inner MAC: Before removing headers, the program loads the inner Ethernet header and stores it over the outer Ethernet header to prevent data loss.
* Room Adjustment: It utilizes bpf_skb_adjust_room with BPF_ADJ_ROOM_MAC to strip the encapsulation while maintaining the integrity of the inner frame.
* Redirect and Protocol Handling: Using bpf_redirect with BPF_F_INGRESS forces the kernel to re-parse the decapsulated frame, ensuring skb->protocol is correctly updated for the inner payload.

### Map Architecture
* erspan_cfg_map: A consolidated ARRAY map using a custom C struct for configuration, minimizing map lookup overhead.
* erspan_stat_map: A PERCPU_ARRAY map for high-speed, contention-free statistics.

