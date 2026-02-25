# Compiler settings
BPF_CLANG ?= clang
CC ?= gcc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Common flags
CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -O2 -g -target bpf -I. -D__TARGET_ARCH_$(ARCH)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo -I/usr/include)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)


# PERSISTENT Configuration
PS_BPF_SRC := persistent_ebpf.c
PS_BPF_OBJ := persistent_ebpf.o
PS_USER_SRC := persistent_loader.c
PS_USER_BIN := persistent_loader
PS_TEST_LOG := persistent_test_output.log

# Persistent runtime parameters (can be overridden)
PS_IFACE ?= veth-recv
PS_REPLAY_IFACE ?= veth-send
PS_PIN_DIR ?= /sys/fs/bpf/persistent
PS_TOPK ?= 50
PS_DURATION ?= 5
# PS_PERSISTENCE_THRESHOLD ?= 7
PS_TRACE ?= ../../dats/2.dat
PS_PCAP ?= ../../pcaps/2.pcap

# Main targets
.PHONY: all help clean
.PHONY: persistent persistent-build persistent-run persistent-setup
.PHONY: test-persistent replay-persistent stop-xdp-persistent

all: help

help:
	@echo "\nPersistent Item Detection eBPF Makefile\n"
	@echo ""
	@echo "Build targets:"
	@echo "  make persistent                            - Build Persistent"
	@echo ""
	@echo "Run targets:"
	@echo "  make persistent-run IFACE=<if>             - Run Persistent (blocking)"
	@echo "  make replay-persistent IFACE=<if>          - Replay packets for Persistent"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-persistent IFACE=<if>            - Full Persistent test"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                                 - Remove all build artifacts"
	@echo "  make stop-xdp-persistent IFACE=<if>        - Detach Persistent XDP"
	@echo ""
	@echo "Persistent parameters (override with VAR=value):"
	@echo "  PS_IFACE=$(PS_IFACE)"
	@echo "  PS_TOPK=$(PS_TOPK)"
	@echo "  PS_DURATION=$(PS_DURATION)"
	@echo "  PS_PERSISTENCE_THRESHOLD=$(PS_PERSISTENCE_THRESHOLD)"
	@echo "  PS_TRACE=$(PS_TRACE)"
	@echo "  PS_PCAP=$(PS_PCAP)"
	@echo ""
	@echo "Examples:"
	@echo "  make persistent IFACE=veth0"
	@echo "  make test-persistent IFACE=veth0 PS_DURATION=5 PS_PERSISTENCE_THRESHOLD=4"


# PERSISTENT BUILD
persistent: persistent-build persistent-setup

persistent-build: $(PS_BPF_OBJ) $(PS_USER_BIN)
	@echo "Persistent built successfully"

$(PS_BPF_OBJ): $(PS_BPF_SRC)
	@echo "Compiling Persistent BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(PS_BPF_SRC) -o $(PS_BPF_OBJ)
	$(LLVM_STRIP) -g $(PS_BPF_OBJ)

$(PS_USER_BIN): $(PS_USER_SRC)
	@echo "Compiling Persistent loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(PS_USER_SRC) -o $(PS_USER_BIN) $(LIBBPF_LDFLAGS) -lm

persistent-setup:
	@echo "Setting up Persistent environment..."
	@sudo ip link set dev $(PS_IFACE) xdp off 2>/dev/null || true
	@sudo rm -r $(PS_PIN_DIR) 2>/dev/null || true
	@sudo mkdir -p $(PS_PIN_DIR)

# RUN TARGETS

persistent-run: persistent-build persistent-setup
	@echo "Running Persistent Item Detection\n"
	@echo "Interface: $(PS_IFACE)"
	@echo "Top-K: $(PS_TOPK)"
	@echo "Duration: $(PS_DURATION)s"
	@echo "Persistence Threshold: $(PS_PERSISTENCE_THRESHOLD) windows"
	@echo ""
	sudo ./$(PS_USER_BIN) -i $(PS_IFACE) -o $(PS_PIN_DIR) -k $(PS_TOPK) -D $(PS_DURATION) -t $(PS_TRACE) $(PS_BPF_OBJ)

# REPLAY TARGETS

replay-persistent:
	@echo "\nReplaying packets for Persistent\n"
	@echo "Interface: $(PS_REPLAY_IFACE)"
	@echo "PCAP: $(PS_PCAP)"
	sudo tcpreplay --intf1=$(PS_REPLAY_IFACE) --topspeed $(PS_PCAP)

# AUTOMATED TEST TARGETS

test-persistent: persistent-build persistent-setup
	@test -f $(PS_BPF_OBJ) || (echo "ERROR: $(PS_BPF_OBJ) not found!"; exit 1)
	@echo "Running Persistent automated test"
	@echo "Starting Persistent in background..."
	@sudo ./$(PS_USER_BIN) -i $(PS_IFACE) -o $(PS_PIN_DIR) -k $(PS_TOPK) -D $(PS_DURATION) -t $(PS_TRACE) $(PS_BPF_OBJ) > persistent_test_output.log 2>&1 & echo $! > /tmp/persistent_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(PS_REPLAY_IFACE) --topspeed $(PS_PCAP) || true
	@echo "Waiting for collection to complete ($(PS_DURATION) seconds)..."
	@sleep $(PS_DURATION)
	@sleep 3
	@echo "Stopping Persistent..."
	@sudo kill -INT $(cat /tmp/persistent_loader.pid 2>/dev/null) 2>/dev/null || true
	@sleep 3
	@echo ""
	@echo "\nPersistent Test Results\n"
	@while [ ! -s persistent_test_output.log ]; do \
		sleep 1; \
	done
	@cat persistent_test_output.log
	@rm -f /tmp/persistent_loader.pid


# STOP XDP

stop-xdp-persistent:
	@echo "Detaching Persistent XDP from $(PS_IFACE)..."
	@sudo ip link set dev $(PS_IFACE) xdp off 2>/dev/null || true

# CLEANUP
clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(PS_BPF_OBJ) $(PS_USER_BIN)
	rm -f $(PS_TEST_LOG)
	rm -f /tmp/persistent_loader.pid
	@echo "Cleaning Persistent pinned maps..."
	@sudo rm -r $(PS_PIN_DIR) 2>/dev/null || true
	@echo "Done"
