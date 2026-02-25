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
# UA-SKETCH Configuration
# ============================================================================
UA_BPF_SRC := uasketch_ebpf.c
UA_BPF_OBJ := uasketch_ebpf.o
UA_USER_SRC := uasketch_loader.c
UA_USER_BIN := uasketch_loader

# UA-Sketch runtime parameters (can be overridden)
UA_IFACE ?= veth-recv
UA_REPLAY_IFACE ?= veth-send
UA_PIN_DIR ?= /sys/fs/bpf/uasketch
UA_TOPK ?= 1000
UA_DURATION ?= 5
UA_TRACE ?= ../dats/10.dat
UA_PCAP ?= ../pcaps/10.pcap

# ============================================================================
# Main targets
# ============================================================================
.PHONY: all help clean
.PHONY: uasketch uasketch-build uasketch-run uasketch-setup
.PHONY: test-uasketch replay-uasketch stop-xdp-uasketch

all: help

help:
	@echo "=== UA-Sketch eBPF Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make uasketch                     - Build UA-Sketch"
	@echo ""
	@echo "Run targets:"
	@echo "  make uasketch-run IFACE=<if>      - Run UA-Sketch (blocking)"
	@echo "  make replay-uasketch IFACE=<if>   - Replay packets for UA-Sketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-uasketch IFACE=<if>     - Full UA-Sketch test"
	@echo ""
	@echo "Utility targets:"
	@echo "  make uasketch-setup               - Setup UA-Sketch environment"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                           - Remove all build artifacts"
	@echo "  make stop-xdp-uasketch IFACE=<if>    - Detach UA-Sketch XDP"
	@echo ""
	@echo "UA-Sketch parameters (override with VAR=value):"
	@echo "  IFACE=$(UA_IFACE)"
	@echo "  UA_TOPK=$(UA_TOPK)"
	@echo "  UA_DURATION=$(UA_DURATION)"
	@echo "  UA_TRACE=$(UA_TRACE)"
	@echo "  UA_PCAP=$(UA_PCAP)"
	@echo "  UA_REPLAY_IFACE=$(UA_REPLAY_IFACE)"
	@echo "  UA_PIN_DIR=$(UA_PIN_DIR)"
	@echo ""
	@echo "Examples:"
	@echo "  make uasketch IFACE=veth0"
	@echo "  make test-uasketch IFACE=veth0 UA_DURATION=5"
	@echo "  make uasketch-run IFACE=veth0 UA_TOPK=500"

# ============================================================================
# UA-SKETCH BUILD
# ============================================================================
uasketch: uasketch-build uasketch-setup

uasketch-build: $(UA_BPF_OBJ) $(UA_USER_BIN)
	@echo "=== UA-Sketch built successfully ==="

$(UA_BPF_OBJ): $(UA_BPF_SRC)
	@echo "Compiling UA-Sketch BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(UA_BPF_SRC) -o $(UA_BPF_OBJ)
	$(LLVM_STRIP) -g $(UA_BPF_OBJ)

$(UA_USER_BIN): $(UA_USER_SRC)
	@echo "Compiling UA-Sketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(UA_USER_SRC) -o $(UA_USER_BIN) $(LIBBPF_LDFLAGS) -lm

uasketch-setup:
	@echo "Setting up UA-Sketch environment..."
	@sudo mkdir -p $(UA_PIN_DIR)
	@sudo rm -f $(UA_PIN_DIR)/* 2>/dev/null || true

# ============================================================================
# RUN TARGETS
# ============================================================================
uasketch-run: uasketch-build uasketch-setup
	@echo "=== Running UA-Sketch ==="
	@echo "Interface: $(UA_IFACE)"
	@echo "Top-K: $(UA_TOPK)"
	@echo "Duration: $(UA_DURATION)s"
	@echo "Trace: $(UA_TRACE)"
	@echo ""
	sudo ./$(UA_USER_BIN) -i $(UA_IFACE) -o $(UA_PIN_DIR) -k $(UA_TOPK) -D $(UA_DURATION) -t $(UA_TRACE) $(UA_BPF_OBJ)

# ============================================================================
# REPLAY TARGETS
# ============================================================================
replay-uasketch:
	@echo "=== Replaying packets for UA-Sketch ==="
	@echo "Interface: $(UA_REPLAY_IFACE)"
	@echo "PCAP: $(UA_PCAP)"
	sudo tcpreplay --intf1=$(UA_REPLAY_IFACE) --topspeed $(UA_PCAP)

# ============================================================================
# AUTOMATED TEST TARGETS
# ============================================================================
test-uasketch: uasketch-build uasketch-setup
	@test -f $(UA_BPF_OBJ) || (echo "ERROR: $(UA_BPF_OBJ) not found!"; exit 1)
	@echo "=== Running UA-Sketch automated test ==="
	@echo "Starting UA-Sketch in background..."
	@sudo ./$(UA_USER_BIN) -i $(UA_IFACE) -o $(UA_PIN_DIR) -k $(UA_TOPK) -D $(UA_DURATION) -t $(UA_TRACE) $(UA_BPF_OBJ) > uasketch_test_output.log 2>&1 & echo $$! > /tmp/uasketch_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(UA_REPLAY_IFACE) --topspeed $(UA_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(UA_DURATION)
	@sleep 2
	@echo "Stopping UA-Sketch..."
	@sudo kill -INT $$(cat /tmp/uasketch_loader.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== UA-Sketch Test Results ==="
	@cat uasketch_test_output.log | tr -d '\r'
	@rm -f /tmp/uasketch_loader.pid

# ============================================================================
# STOP XDP
# ============================================================================
stop-xdp-uasketch:
	@echo "Detaching UA-Sketch XDP from $(UA_IFACE)..."
	@sudo ip link set dev $(UA_IFACE) xdp off 2>/dev/null || true

# ============================================================================
# CLEANUP
# ============================================================================
clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(UA_BPF_OBJ) $(UA_USER_BIN)
	rm -f uasketch_test_output.log
	rm -f /tmp/uasketch_loader.pid
	@echo "Cleaning UA-Sketch pinned maps..."
	@sudo rm -rf $(UA_PIN_DIR) 2>/dev/null || true
	@echo "Done"