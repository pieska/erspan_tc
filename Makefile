# name
TARGET = erspan_decap

# interface to bind filter to
IFACE = veth2_mirror

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
	@tc qdisc add dev $(IFACE) clsact
	@tc filter replace dev $(IFACE) egress pref 1 bpf da obj $(TARGET).o sec classifier

unload:
	@tc qdisc del dev $(IFACE) clsact

reload: unload $(TARGET).o load

trace:
	@cat /sys/kernel/debug/tracing/trace_pipe

set_sessionid:
	@if [ -z "$(ID)" ]; then echo "ERROR: missing ID. usage: make set_sessionid ID=xyz"; exit 1; fi
	@MAP_ID=$$($(BPFTOOL) map show name config_map -j | jq -r 'if type=="array" then .[0].id else .id end // empty');
	@if [ -z "$$MAP_ID" ]; then \
		echo "ERROR: map 'config_map' not found."; \
	else \
		LOW=$$(printf "0x%02x" $$(($(ID) % 256))); \
		HIGH=$$(printf "0x%02x" $$(($(ID) / 256))); \
		$(BPFTOOL) map update id $$MAP_ID key 0x00 0x00 0x00 0x00 value $$LOW $$HIGH; \
		echo "session-ID set to $(ID)."; \
	fi

get_sessionid:
	@MAP_ID=$$($(BPFTOOL) map show name config_map -j | jq -r 'if type=="array" then .[0].id else .id end // empty');
	@if [ -z "$$MAP_ID" ]; then \
		echo "ERROR: map not found."; \
	else \
		VAL=$$($(BPFTOOL) map lookup id $$MAP_ID key 0x00 0x00 0x00 0x00 -j | jq -r '.formatted.value // .value'); \
		echo "current set session-ID: $$VAL"; \
	fi

clean:
	rm -f $(TARGET).o

.PHONY: release debug load unload reload trace clean set_sessionid get_sessionid

