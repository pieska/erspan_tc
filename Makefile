# name
TARGET = erspan_decap

# default attach interface and direction (can be overridden via command line)
DEV ?= veth2_mirror
DIR ?= egress

CLANG = clang
BPFTOOL = bpftool

INCLUDES = -I/usr/include -I/usr/include/x86_64-linux-gnu
CFLAGS = -O2 -g -target bpf $(INCLUDES) -D__TARGET_ARCH_x86

$(TARGET).o: $(TARGET).c
	$(CLANG) $(CFLAGS) -c $< -o $@

release: CFLAGS += -UDEBUG
release: $(TARGET).o

debug: CFLAGS += -DDEBUG
debug: $(TARGET).o

load:
	@echo "Loading $(TARGET) on $(DEV) ($(DIR))..."
	@tc qdisc add dev $(DEV) clsact 2>/dev/null || true
	@tc filter replace dev $(DEV) $(DIR) pref 1 bpf da obj $(TARGET).o sec classifier

unload:
	@echo "Unloading $(TARGET) from $(DEV)..."
	@tc qdisc del dev $(DEV) clsact 2>/dev/null || true

reload: unload $(TARGET).o load

trace:
	@cat /sys/kernel/debug/tracing/trace_pipe

set_config:
	@if [ -z "$(ID)" ] || [ -z "$(TARGET_DEV)" ]; then \
		echo "ERROR: missing ID or TARGET_DEV. usage: make set_config ID=100 TARGET_DEV=dummy0"; exit 1; \
	fi
	@if [ ! -f "/sys/class/net/$(TARGET_DEV)/ifindex" ]; then \
		echo "ERROR: interface '$(TARGET_DEV)' not found in sysfs."; exit 1; \
	fi
	@REAL_IFINDEX=$$(cat /sys/class/net/$(TARGET_DEV)/ifindex); \
	MAP_ID=$$($(BPFTOOL) map show name erspan_cfg_map -j | jq -r 'if type=="array" then .[0].id else .id end // empty'); \
	if [ -z "$$MAP_ID" ]; then \
		echo "ERROR: map 'erspan_cfg_map' not found."; \
	else \
		IF0=$$(printf "%02x" $$(($$REAL_IFINDEX & 255))); \
		IF1=$$(printf "%02x" $$((($$REAL_IFINDEX >> 8) & 255))); \
		IF2=$$(printf "%02x" $$((($$REAL_IFINDEX >> 16) & 255))); \
		IF3=$$(printf "%02x" $$((($$REAL_IFINDEX >> 24) & 255))); \
		ID0=$$(printf "%02x" $$(($(ID) & 255))); \
		ID1=$$(printf "%02x" $$((($(ID) >> 8) & 255))); \
		$(BPFTOOL) map update id $$MAP_ID key hex 00 00 00 00 value hex $$IF0 $$IF1 $$IF2 $$IF3 $$ID0 $$ID1 00 00; \
		echo "Config set: TARGET_DEV=$(TARGET_DEV) (Index: $$REAL_IFINDEX), Session-ID=$(ID)."; \
	fi

get_config:
	@MAP_ID=$$($(BPFTOOL) map show name erspan_cfg_map -j | jq -r 'if type=="array" then .[0].id else .id end // empty'); \
	if [ -z "$$MAP_ID" ]; then \
		echo "ERROR: map 'erspan_cfg_map' not found."; \
	else \
		echo "Current erspan_cfg_map contents (Little-Endian Hex):"; \
		echo "[ IFINDEX (4B) ] [ ID (2B) ] [ PAD (2B) ]"; \
		$(BPFTOOL) map dump id $$MAP_ID; \
	fi

get_stats:
	@MAP_ID=$$($(BPFTOOL) map show name erspan_stat_map -j | jq -r 'if type=="array" then .[0].id else .id end // empty'); \
	if [ -z "$$MAP_ID" ]; then \
		echo "ERROR: map 'erspan_stat_map' not found."; \
	else \
		echo "=== ERSPAN Decap Statistics (Per-CPU) ==="; \
		echo "Layout per CPU: [ rx_packets (8B) ] [ rx_bytes (8B) ] [ drop_session_filtered (8B) ] [ drop_errors (8B) ]"; \
		$(BPFTOOL) map dump id $$MAP_ID; \
	fi

clean:
	rm -f $(TARGET).o

.PHONY: release debug load unload reload trace clean set_config get_config get_stats

