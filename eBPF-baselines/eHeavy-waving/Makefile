BPF_CLANG ?= clang
CC ?= gcc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -O2 -g -target bpf -I. -D__TARGET_ARCH_$(ARCH)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo -I/usr/include)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)


WS_BPF_SRC := wavingsketch_ebpf.c
WS_BPF_OBJ := wavingsketch_ebpf.o
WS_USER_SRC := wavingsketch_loader.c
WS_USER_BIN := wavingsketch_loader


WS_IFACE ?= veth-recv
WS_REPLAY_IFACE ?= veth-send
WS_PIN_DIR ?= /sys/fs/bpf/wavingsketch
WS_TOPK ?= 1000
WS_DURATION ?= 5
WS_TRACE ?= ../dats/10.dat
WS_PCAP ?= ../pcaps/10.pcap


.PHONY: all help clean
.PHONY: wavingsketch wavingsketch-build wavingsketch-run wavingsketch-setup
.PHONY: test-wavingsketch replay-wavingsketch stop-xdp-wavingsketch

all: help

help:
	@echo "=== WavingSketch eBPF Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make wavingsketch                     - Build WavingSketch"
	@echo ""
	@echo "Run targets:"
	@echo "  make wavingsketch-run IFACE=<if>      - Run WavingSketch (blocking)"
	@echo "  make replay-wavingsketch IFACE=<if>   - Replay packets for WavingSketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-wavingsketch IFACE=<if>     - Full WavingSketch test"
	@echo ""
	@echo "Utility targets:"
	@echo "  make wavingsketch-setup               - Setup WavingSketch environment"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                               - Remove all build artifacts"
	@echo "  make stop-xdp-wavingsketch IFACE=<if>   - Detach WavingSketch XDP"
	@echo ""
	@echo "WavingSketch parameters (override with VAR=value):"
	@echo "  IFACE=$(WS_IFACE)"
	@echo "  WS_TOPK=$(WS_TOPK)"
	@echo "  WS_DURATION=$(WS_DURATION)"
	@echo "  WS_TRACE=$(WS_TRACE)"
	@echo "  WS_PCAP=$(WS_PCAP)"
	@echo "  WS_REPLAY_IFACE=$(WS_REPLAY_IFACE)"
	@echo "  WS_PIN_DIR=$(WS_PIN_DIR)"
	@echo ""
	@echo "Examples:"
	@echo "  make wavingsketch IFACE=veth0"
	@echo "  make test-wavingsketch IFACE=veth0 WS_DURATION=5"
	@echo "  make wavingsketch-run IFACE=veth0 WS_TOPK=500"

wavingsketch: wavingsketch-build wavingsketch-setup

wavingsketch-build: $(WS_BPF_OBJ) $(WS_USER_BIN)
	@echo "=== WavingSketch built successfully ==="

$(WS_BPF_OBJ): $(WS_BPF_SRC)
	@echo "Compiling WavingSketch BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(WS_BPF_SRC) -o $(WS_BPF_OBJ)
	$(LLVM_STRIP) -g $(WS_BPF_OBJ)

$(WS_USER_BIN): $(WS_USER_SRC)
	@echo "Compiling WavingSketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(WS_USER_SRC) -o $(WS_USER_BIN) $(LIBBPF_LDFLAGS) -lm

wavingsketch-setup:
	@echo "Setting up WavingSketch environment..."
	@sudo mkdir -p $(WS_PIN_DIR)
	@sudo rm -f $(WS_PIN_DIR)/* 2>/dev/null || true

wavingsketch-run: wavingsketch-build wavingsketch-setup
	@echo "=== Running WavingSketch ==="
	@echo "Interface: $(WS_IFACE)"
	@echo "Top-K: $(WS_TOPK)"
	@echo "Duration: $(WS_DURATION)s"
	@echo "Trace: $(WS_TRACE)"
	@echo ""
	sudo ./$(WS_USER_BIN) -i $(WS_IFACE) -o $(WS_PIN_DIR) -k $(WS_TOPK) -D $(WS_DURATION) -t $(WS_TRACE) $(WS_BPF_OBJ)


replay-wavingsketch:
	@echo "=== Replaying packets for WavingSketch ==="
	@echo "Interface: $(WS_REPLAY_IFACE)"
	@echo "PCAP: $(WS_PCAP)"
	sudo tcpreplay --intf1=$(WS_REPLAY_IFACE) --topspeed $(WS_PCAP)

test-wavingsketch: wavingsketch-build wavingsketch-setup
	@test -f $(WS_BPF_OBJ) || (echo "ERROR: $(WS_BPF_OBJ) not found!"; exit 1)
	@echo "=== Running WavingSketch automated test ==="
	@echo "Starting WavingSketch in background..."
	@sudo ./$(WS_USER_BIN) -i $(WS_IFACE) -o $(WS_PIN_DIR) -k $(WS_TOPK) -D $(WS_DURATION) -t $(WS_TRACE) $(WS_BPF_OBJ) > wavingsketch_test_output.log 2>&1 & echo $$! > /tmp/wavingsketch_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(WS_REPLAY_IFACE) --topspeed $(WS_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(WS_DURATION)
	@sleep 2
	@echo "Stopping WavingSketch..."
	@sudo kill -INT $$(cat /tmp/wavingsketch_loader.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== WavingSketch Test Results ==="
	@cat wavingsketch_test_output.log | tr -d '\r'
	@rm -f /tmp/wavingsketch_loader.pid

stop-xdp-wavingsketch:
	@echo "Detaching WavingSketch XDP from $(WS_IFACE)..."
	@sudo ip link set dev $(WS_IFACE) xdp off 2>/dev/null || true

clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(WS_BPF_OBJ) $(WS_USER_BIN)
	rm -f wavingsketch_test_output.log
	rm -f /tmp/wavingsketch_loader.pid
	@echo "Cleaning WavingSketch pinned maps..."
	@sudo rm -rf $(WS_PIN_DIR) 2>/dev/null || true
	@echo "Done"
