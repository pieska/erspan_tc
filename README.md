# erspan_tc
eBPF tc-filter to remove ERSPAN header

# packages for build
make
clang
libbpf-devel

# packages for makefile targets
iproute
bpftool
jq

# makefile
IFACE=veth2_mirror -> device to bind filter on

make debug -> debug version
make release -> release version
make load -> create qdisc and binds filter on IFACE
make unload -> removes qdisc and all attached filter from IFACE
make reload -> unload, build, load
make trace -> cat /sys/kernel/debug/tracing/trace_pipe to get bpf_printk() output
make set_sessionid -> sets sessionid in bpf configmap to filter erspan sessions
make get_sessionid -> gets sessionid from bpf configmap
make clean -> cleanup

# demosetup

# veth-pairs, aci -> veth2, veth2_mirror -> span
ip link add veth2 type veth peer name aci
ip link add span type veth peer name veth2_mirror

# jumbo frames
ip link set veth2 mtu 9000
ip link set span mtu 9000
ip link set veth2_mirror mtu 9000
ip link set aci mtu 9000

# promisc on port-mirror ports
ip link set span promisc on
ip link set veth2_mirror promisc on

# IP on erspan-endpoint
ip addr add 10.10.3.150/24 dev veth2

# all up

ip link set veth2 up
ip link set span up
ip link set veth2_mirror up
ip link set aci up

# mirror veth2 nach veth2_mirror, ingress
tc qdisc add dev veth2 handle ffff: ingress
tc filter add dev veth2 ingress matchall action mirred egress mirror dev veth2_mirror

# make load loads filter on veth2_mirror egress
tc qdisc add dev veth2_mirror clsact
tc filter add dev veth2_mirror egress bpf da obj erspan_decap.o sec classifier

