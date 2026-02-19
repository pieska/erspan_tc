# erspan_tc

An eBPF-based Traffic Control (TC) filter designed to decapsulate ERSPAN Type II traffic and redirect the inner frames to a target interface.

## Requirements

### Build Dependencies
* `make`
* `clang`
* `libbpf-devel`

### Runtime Dependencies
* `iproute2`
* `bpftool`
* `jq` (required for Makefile automation)
* `python3-scapy` (optional, for testing)

---

## Makefile Targets

| Target | Description |
| :--- | :--- |
| `make debug` | Compiles the BPF object with the `DEBUG` flag enabled. |
| `make release` | Compiles a clean version without debug symbols/output. |
| `make load` | Attaches the filter to `DEV` (Default: `veth2_mirror`) at `DIR` (Default: `egress`). |
| `make unload` | Detaches the filter and removes the `clsact` qdisc. |
| `make reload` | Performs unload, recompiles, and loads the filter again. |
| `make set_config` | Sets redirect target and Session ID. Usage: `make set_config ID=100 IFACE=dummy0`. |
| `make get_config` | Displays current configuration from the `erspan_cfg_map`. |
| `make get_stats` | Displays decapsulation statistics per CPU from `erspan_stat_map`. |
| `make trace` | Streams `bpf_printk()` output from the kernel trace pipe. |
| `make clean` | Removes compiled object files. |

---

## Setup Examples

### 1. Basic Setup (No Redirect)
In this scenario, the filter decapsulates packets and passes them back to the networking stack on the same interface.

```bash
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

