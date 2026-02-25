# ============================================================================
# HeavyGuardian eBPF Makefile
# Usage:
#   make heavyguardian IFACE=veth0       - Build and test HeavyGuardian
#   make test-heavyguardian IFACE=veth0  - Full automated test for HeavyGuardian
# ============================================================================

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

# ============================================================================
# HEAVYGUARDIAN Configuration
# ============================================================================
HG_BPF_SRC := heavyguardian_ebpf.c
HG_BPF_OBJ := heavyguardian_ebpf.o
HG_USER_SRC := heavyguardian_loader.c
HG_USER_BIN := heavyguardian_loader

# HeavyGuardian runtime parameters (can be overridden)
HG_IFACE ?= veth-recv
HG_REPLAY_IFACE ?= veth-send
HG_PIN_DIR ?= /sys/fs/bpf/heavyguardian
HG_TOPK ?= 1000
HG_DURATION ?= 5
HG_TRACE ?= ../dats/10.dat
HG_PCAP ?= ../pcaps/10.pcap

# ============================================================================
# Main targets
# ============================================================================
.PHONY: all help clean
.PHONY: heavyguardian heavyguardian-build heavyguardian-run heavyguardian-setup
.PHONY: test-heavyguardian replay-heavyguardian stop-xdp-heavyguardian

all: help

help:
	@echo "=== HeavyGuardian eBPF Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make heavyguardian                     - Build HeavyGuardian"
	@echo ""
	@echo "Run targets:"
	@echo "  make heavyguardian-run IFACE=<if>      - Run HeavyGuardian (blocking)"
	@echo "  make replay-heavyguardian IFACE=<if>   - Replay packets for HeavyGuardian"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-heavyguardian IFACE=<if>     - Full HeavyGuardian test"
	@echo ""
	@echo "Utility targets:"
	@echo "  make heavyguardian-setup               - Setup HeavyGuardian environment"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                           - Remove all build artifacts"
	@echo "  make stop-xdp-heavyguardian IFACE=<if> - Detach HeavyGuardian XDP"
	@echo ""
	@echo "HeavyGuardian parameters (override with VAR=value):"
	@echo "  IFACE=$(HG_IFACE)"
	@echo "  HG_TOPK=$(HG_TOPK)"
	@echo "  HG_DURATION=$(HG_DURATION)"
	@echo "  HG_TRACE=$(HG_TRACE)"
	@echo "  HG_PCAP=$(HG_PCAP)"
	@echo "  HG_REPLAY_IFACE=$(HG_REPLAY_IFACE)"
	@echo "  HG_PIN_DIR=$(HG_PIN_DIR)"
	@echo ""
	@echo "Examples:"
	@echo "  make heavyguardian IFACE=veth0"
	@echo "  make test-heavyguardian IFACE=veth0 HG_DURATION=5"
	@echo "  make heavyguardian-run IFACE=veth0 HG_TOPK=500"

# ============================================================================
# HEAVYGUARDIAN BUILD
# ============================================================================
heavyguardian: heavyguardian-build heavyguardian-setup

heavyguardian-build: $(HG_BPF_OBJ) $(HG_USER_BIN)
	@echo "=== HeavyGuardian built successfully ==="

$(HG_BPF_OBJ): $(HG_BPF_SRC)
	@echo "Compiling HeavyGuardian BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(HG_BPF_SRC) -o $(HG_BPF_OBJ)
	$(LLVM_STRIP) -g $(HG_BPF_OBJ)

$(HG_USER_BIN): $(HG_USER_SRC)
	@echo "Compiling HeavyGuardian loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(HG_USER_SRC) -o $(HG_USER_BIN) $(LIBBPF_LDFLAGS) -lm

heavyguardian-setup:
	@echo "Setting up HeavyGuardian environment..."
	@sudo mkdir -p $(HG_PIN_DIR)
	@sudo rm -f $(HG_PIN_DIR)/* 2>/dev/null || true

# ============================================================================
# RUN TARGETS
# ============================================================================
heavyguardian-run: heavyguardian-build heavyguardian-setup
	@echo "=== Running HeavyGuardian ==="
	@echo "Interface: $(HG_IFACE)"
	@echo "Top-K: $(HG_TOPK)"
	@echo "Duration: $(HG_DURATION)s"
	@echo "Trace: $(HG_TRACE)"
	@echo ""
	sudo ./$(HG_USER_BIN) -i $(HG_IFACE) -o $(HG_PIN_DIR) -k $(HG_TOPK) -D $(HG_DURATION) -t $(HG_TRACE) $(HG_BPF_OBJ)

# ============================================================================
# REPLAY TARGETS
# ============================================================================
replay-heavyguardian:
	@echo "=== Replaying packets for HeavyGuardian ==="
	@echo "Interface: $(HG_REPLAY_IFACE)"
	@echo "PCAP: $(HG_PCAP)"
	sudo tcpreplay --intf1=$(HG_REPLAY_IFACE) --topspeed $(HG_PCAP)

# ============================================================================
# AUTOMATED TEST TARGETS
# ============================================================================
test-heavyguardian: heavyguardian-build heavyguardian-setup
	@test -f $(HG_BPF_OBJ) || (echo "ERROR: $(HG_BPF_OBJ) not found!"; exit 1)
	@echo "=== Running HeavyGuardian automated test ==="
	@echo "Starting HeavyGuardian in background..."
	@sudo ./$(HG_USER_BIN) -i $(HG_IFACE) -o $(HG_PIN_DIR) -k $(HG_TOPK) -D $(HG_DURATION) -t $(HG_TRACE) $(HG_BPF_OBJ) > heavyguardian_test_output.log 2>&1 & echo $$! > /tmp/heavyguardian_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(HG_REPLAY_IFACE) --topspeed $(HG_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(HG_DURATION)
	@sleep 2
	@echo "Stopping HeavyGuardian..."
	@sudo kill -INT $$(cat /tmp/heavyguardian_loader.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== HeavyGuardian Test Results ==="
	@cat heavyguardian_test_output.log | tr -d '\r'
	@rm -f /tmp/heavyguardian_loader.pid

# ============================================================================
# STOP XDP
# ============================================================================
stop-xdp-heavyguardian:
	@echo "Detaching HeavyGuardian XDP from $(HG_IFACE)..."
	@sudo ip link set dev $(HG_IFACE) xdp off 2>/dev/null || true

# ============================================================================
# CLEANUP
# ============================================================================
clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(HG_BPF_OBJ) $(HG_USER_BIN)
	rm -f heavyguardian_test_output.log
	rm -f /tmp/heavyguardian_loader.pid
	@echo "Cleaning HeavyGuardian pinned maps..."
	@sudo rm -rf $(HG_PIN_DIR) 2>/dev/null || true
	@echo "Done"