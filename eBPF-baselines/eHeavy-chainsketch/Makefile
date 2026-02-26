BPF_CLANG ?= clang
CC ?= gcc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -O2 -g -target bpf -I. -D__TARGET_ARCH_$(ARCH)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo -I/usr/include)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)


CHAIN_BPF_SRC := chainsketch_ebpf.c
CHAIN_BPF_OBJ := chainsketch_ebpf.o
CHAIN_USER_SRC := chainsketch_loader.c
CHAIN_USER_BIN := chainsketch_loader

CHAIN_IFACE ?= veth-recv
CHAIN_REPLAY_IFACE ?= veth-send
CHAIN_PIN_DIR ?= /sys/fs/bpf/chainsketch
CHAIN_TOPK ?= 1000
CHAIN_DURATION ?= 5
CHAIN_TRACE ?= ../dats/10.dat
CHAIN_PCAP ?= ../pcaps/10.pcap


.PHONY: all help clean
.PHONY: chainsketch chainsketch-build chainsketch-run chainsketch-setup
.PHONY: test-chainsketch replay-chainsketch stop-xdp-chainsketch

all: help

help:
	@echo "=== ChainSketch eBPF Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make chainsketch                     - Build ChainSketch"
	@echo ""
	@echo "Run targets:"
	@echo "  make chainsketch-run IFACE=<if>      - Run ChainSketch (blocking)"
	@echo "  make replay-chainsketch IFACE=<if>   - Replay packets for ChainSketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-chainsketch IFACE=<if>     - Full ChainSketch test"
	@echo ""
	@echo "Utility targets:"
	@echo "  make chainsketch-setup               - Setup ChainSketch environment"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                           - Remove all build artifacts"
	@echo "  make stop-xdp-chainsketch IFACE=<if> - Detach ChainSketch XDP"
	@echo ""
	@echo "ChainSketch parameters (override with VAR=value):"
	@echo "  IFACE=$(CHAIN_IFACE)"
	@echo "  CHAIN_TOPK=$(CHAIN_TOPK)"
	@echo "  CHAIN_DURATION=$(CHAIN_DURATION)"
	@echo "  CHAIN_TRACE=$(CHAIN_TRACE)"
	@echo "  CHAIN_PCAP=$(CHAIN_PCAP)"
	@echo "  CHAIN_REPLAY_IFACE=$(CHAIN_REPLAY_IFACE)"
	@echo "  CHAIN_PIN_DIR=$(CHAIN_PIN_DIR)"
	@echo ""
	@echo "Examples:"
	@echo "  make chainsketch IFACE=veth0"
	@echo "  make test-chainsketch IFACE=veth0 CHAIN_DURATION=5"
	@echo "  make chainsketch-run IFACE=veth0 CHAIN_TOPK=500"

chainsketch: chainsketch-build chainsketch-setup

chainsketch-build: $(CHAIN_BPF_OBJ) $(CHAIN_USER_BIN)
	@echo "=== ChainSketch built successfully ==="

$(CHAIN_BPF_OBJ): $(CHAIN_BPF_SRC)
	@echo "Compiling ChainSketch BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(CHAIN_BPF_SRC) -o $(CHAIN_BPF_OBJ)
	$(LLVM_STRIP) -g $(CHAIN_BPF_OBJ)

$(CHAIN_USER_BIN): $(CHAIN_USER_SRC)
	@echo "Compiling ChainSketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(CHAIN_USER_SRC) -o $(CHAIN_USER_BIN) $(LIBBPF_LDFLAGS)

chainsketch-setup:
	@echo "Setting up ChainSketch environment..."
	@sudo mkdir -p $(CHAIN_PIN_DIR)
	@sudo rm -f $(CHAIN_PIN_DIR)/* 2>/dev/null || true


chainsketch-run: chainsketch-build chainsketch-setup
	@echo "=== Running ChainSketch ==="
	@echo "Interface: $(CHAIN_IFACE)"
	@echo "Top-K: $(CHAIN_TOPK)"
	@echo "Duration: $(CHAIN_DURATION)s"
	@echo "Trace: $(CHAIN_TRACE)"
	@echo ""
	sudo ./$(CHAIN_USER_BIN) -i $(CHAIN_IFACE) -o $(CHAIN_PIN_DIR) -k $(CHAIN_TOPK) -D $(CHAIN_DURATION) -t $(CHAIN_TRACE) $(CHAIN_BPF_OBJ)


replay-chainsketch:
	@echo "=== Replaying packets for ChainSketch ==="
	@echo "Interface: $(CHAIN_REPLAY_IFACE)"
	@echo "PCAP: $(CHAIN_PCAP)"
	sudo tcpreplay --intf1=$(CHAIN_REPLAY_IFACE) --topspeed $(CHAIN_PCAP)


test-chainsketch: chainsketch-build chainsketch-setup
	@test -f $(CHAIN_BPF_OBJ) || (echo "ERROR: $(CHAIN_BPF_OBJ) not found!"; exit 1)
	@echo "=== Running ChainSketch automated test ==="
	@echo "Starting ChainSketch in background..."
	@sudo ./$(CHAIN_USER_BIN) -i $(CHAIN_IFACE) -o $(CHAIN_PIN_DIR) -k $(CHAIN_TOPK) -D $(CHAIN_DURATION) -t $(CHAIN_TRACE) $(CHAIN_BPF_OBJ) > chainsketch_test_output.log 2>&1 & echo $$! > /tmp/chainsketch_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(CHAIN_REPLAY_IFACE) --topspeed $(CHAIN_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(CHAIN_DURATION)
	@sleep 2
	@echo "Stopping ChainSketch..."
	@sudo kill -INT $$(cat /tmp/chainsketch_loader.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== ChainSketch Test Results ==="
	@cat chainsketch_test_output.log | tr -d '\r'
	@rm -f /tmp/chainsketch_loader.pid


stop-xdp-chainsketch:
	@echo "Detaching ChainSketch XDP from $(CHAIN_IFACE)..."
	@sudo ip link set dev $(CHAIN_IFACE) xdp off 2>/dev/null || true


clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(CHAIN_BPF_OBJ) $(CHAIN_USER_BIN)
	rm -f chainsketch_test_output.log
	rm -f /tmp/chainsketch_loader.pid
	@echo "Cleaning ChainSketch pinned maps..."
	@sudo rm -rf $(CHAIN_PIN_DIR) 2>/dev/null || true
	@echo "Done"
