
BPF_CLANG ?= clang
CC ?= gcc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -O2 -g -target bpf -I. -D__TARGET_ARCH_$(ARCH)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo -I/usr/include)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

STABLE_BPF_SRC := stable_sketch_ebpf.c
STABLE_BPF_OBJ := stable_sketch_ebpf.o
STABLE_SKEL := stable_sketch_ebpf.skel.h
STABLE_USER_SRC := stable_sketch_user.c
STABLE_USER_BIN := stable_sketch_user
STABLE_COMMON := stable_sketch_common.h

STABLE_IFACE ?= veth-recv
STABLE_TOPK ?= 1000
STABLE_DURATION ?= 10
STABLE_TRACE ?= ./10.dat
STABLE_PCAP ?= ./packets_from_dat.pcap
STABLE_REPLAY_IFACE ?= veth-send


JIGSAW_BPF_SRC := jigsaw_xdp.c
JIGSAW_BPF_OBJ := jigsaw_xdp.o
JIGSAW_USER_SRC := jigsaw_loader.c
JIGSAW_USER_BIN := jigsaw_loader

JIGSAW_IFACE ?= veth0
JIGSAW_REPLAY_IFACE ?= veth1
JIGSAW_PIN_DIR ?= /sys/fs/bpf/jigsaw
JIGSAW_TOPK ?= 1000
JIGSAW_DURATION ?= 10
JIGSAW_TRACE ?= ./dats/jigsaw_2.dat
JIGSAW_PCAP ?= ./pcaps/2.pcap

FOURFA_BPF_SRC := fourfa_sketch_ebpf.c
FOURFA_BPF_OBJ := fourfa_sketch_ebpf.o
FOURFA_SKEL := fourfa_sketch_ebpf.skel.h
FOURFA_USER_SRC := fourfa_sketch_loader.c
FOURFA_USER_BIN := fourfa_sketch_loader
FOURFA_COMMON := fourfa_sketch_common.h

FOURFA_IFACE ?= veth-recv
FOURFA_REPLAY_IFACE ?= veth-send
FOURFA_DURATION ?= 10
FOURFA_TOPK ?= 1000
FOURFA_PCAP ?= ./packets_from_dat.pcap


VMLINUX := vmlinux.h


.PHONY: all help clean clean-all vmlinux
.PHONY: stable jigsaw fourfa
.PHONY: stable-build jigsaw-build fourfa-build
.PHONY: stable-run jigsaw-run fourfa-run
.PHONY: test-stable test-jigsaw test-fourfa
.PHONY: replay-stable replay-jigsaw replay-fourfa
.PHONY: stop-xdp-stable stop-xdp-jigsaw stop-xdp-fourfa

all: help

help:
	@echo "=== Unified eBPF Sketch Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make stable         - Build StableSketch"
	@echo "  make jigsaw         - Build Jigsaw"
	@echo "  make fourfa         - Build 4FASketch"
	@echo "  make all           - Show this help"
	@echo ""
	@echo "Run targets:"
	@echo "  make stable-run IFACE=<if>           - Run StableSketch (blocking)"
	@echo "  make jigsaw-run IFACE=<if>           - Run Jigsaw (blocking)"
	@echo "  make fourfa-run IFACE=<if>           - Run 4FASketch (blocking)"
	@echo "  make replay-stable IFACE=<if>        - Replay packets for StableSketch"
	@echo "  make replay-jigsaw IFACE=<if>        - Replay packets for Jigsaw"
	@echo "  make replay-fourfa IFACE=<if>       - Replay packets for 4FASketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-stable IFACE=<if>          - Full StableSketch test"
	@echo "  make test-jigsaw IFACE=<if>          - Full Jigsaw test"
	@echo "  make test-fourfa IFACE=<if>          - Full 4FASketch test"
	@echo ""
	@echo "Utility targets:"
	@echo "  make setup-veth                      - Setup veth pair (veth-send/veth-recv)"
	@echo "  make teardown-veth                   - Remove veth pair"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                           - Remove all build artifacts"
	@echo "  make stop-xdp-stable IFACE=<if>      - Detach StableSketch XDP"
	@echo "  make stop-xdp-jigsaw IFACE=<if>      - Detach Jigsaw XDP"
	@echo ""
	@echo "StableSketch parameters (override with VAR=value):"
	@echo "  IFACE=$(STABLE_IFACE)"
	@echo "  STABLE_TOPK=$(STABLE_TOPK)"
	@echo "  STABLE_DURATION=$(STABLE_DURATION)"
	@echo "  STABLE_TRACE=$(STABLE_TRACE)"
	@echo "  STABLE_PCAP=$(STABLE_PCAP)"
	@echo "  STABLE_REPLAY_IFACE=$(STABLE_REPLAY_IFACE)"
	@echo ""
	@echo "Jigsaw parameters (override with VAR=value):"
	@echo "  IFACE=$(JIGSAW_IFACE)"
	@echo "  JIGSAW_TOPK=$(JIGSAW_TOPK)"
	@echo "  JIGSAW_DURATION=$(JIGSAW_DURATION)"
	@echo "  JIGSAW_TRACE=$(JIGSAW_TRACE)"
	@echo "  JIGSAW_PCAP=$(JIGSAW_PCAP)"
	@echo "  JIGSAW_REPLAY_IFACE=$(JIGSAW_REPLAY_IFACE)"
	@echo "  JIGSAW_PIN_DIR=$(JIGSAW_PIN_DIR)"
	@echo ""
	@echo "4FASketch parameters (override with VAR=value):"
	@echo "  IFACE=$(FOURFA_IFACE)"
	@echo "  FOURFA_TOPK=$(FOURFA_TOPK)"
	@echo "  FOURFA_DURATION=$(FOURFA_DURATION)"
	@echo "  FOURFA_PCAP=$(FOURFA_PCAP)"
	@echo "  FOURFA_REPLAY_IFACE=$(FOURFA_REPLAY_IFACE)"
	@echo ""
	@echo "Examples:"
	@echo "  make stable IFACE=veth-recv"
	@echo "  make test-stable IFACE=veth-recv STABLE_TOPK=500"
	@echo "  make jigsaw IFACE=veth0"
	@echo "  make test-jigsaw IFACE=veth0 JIGSAW_DURATION=5"
	@echo "  make fourfa IFACE=veth-recv"
	@echo "  sudo make test-fourfa IFACE=veth-recv FOURFA_TOPK=500"


$(VMLINUX):
	@echo "Generating vmlinux.h..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

vmlinux: $(VMLINUX)


stable: stable-build

stable-build: $(STABLE_USER_BIN)
	@echo "=== StableSketch built successfully ==="

$(STABLE_BPF_OBJ): $(STABLE_BPF_SRC) $(STABLE_COMMON) $(VMLINUX)
	@echo "Compiling StableSketch BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(STABLE_BPF_SRC) -o $(STABLE_BPF_OBJ)
	$(LLVM_STRIP) -g $(STABLE_BPF_OBJ)

$(STABLE_SKEL): $(STABLE_BPF_OBJ)
	@echo "Generating StableSketch skeleton..."
	$(BPFTOOL) gen skeleton $(STABLE_BPF_OBJ) > $(STABLE_SKEL)

$(STABLE_USER_BIN): $(STABLE_USER_SRC) $(STABLE_SKEL) $(STABLE_COMMON)
	@echo "Compiling StableSketch userspace program..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(STABLE_USER_SRC) -o $(STABLE_USER_BIN) $(LIBBPF_LDFLAGS)


jigsaw: jigsaw-build jigsaw-setup

jigsaw-build: $(JIGSAW_BPF_OBJ) $(JIGSAW_USER_BIN) 
	@echo "=== Jigsaw built successfully ==="

$(JIGSAW_BPF_OBJ): $(JIGSAW_BPF_SRC)
	@echo "Compiling Jigsaw BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(JIGSAW_BPF_SRC) -o $(JIGSAW_BPF_OBJ)

$(JIGSAW_USER_BIN): $(JIGSAW_USER_SRC)
	@echo "Compiling Jigsaw loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(JIGSAW_USER_SRC) -o $(JIGSAW_USER_BIN) $(LIBBPF_LDFLAGS)

jigsaw-setup:
	@echo "Setting up Jigsaw environment..."
	@sudo mkdir -p $(JIGSAW_PIN_DIR)
	@sudo rm -f $(JIGSAW_PIN_DIR)/aux_map $(JIGSAW_PIN_DIR)/bucket_map $(JIGSAW_PIN_DIR)/xdp_stats_map 2>/dev/null || true


fourfa: fourfa-build

fourfa-build: $(FOURFA_USER_BIN)
	@echo "=== 4FASketch built successfully ==="

$(FOURFA_BPF_OBJ): $(FOURFA_BPF_SRC) $(FOURFA_COMMON)
	@echo "Compiling 4FASketch BPF program"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(FOURFA_BPF_SRC) -o $(FOURFA_BPF_OBJ)

$(FOURFA_SKEL): $(FOURFA_BPF_OBJ)
	@echo "Generating 4FASketch skeleton..."
	$(BPFTOOL) gen skeleton $(FOURFA_BPF_OBJ) > $(FOURFA_SKEL)

$(FOURFA_USER_BIN): $(FOURFA_USER_SRC) $(FOURFA_SKEL) $(FOURFA_COMMON)
	@echo "Compiling 4FASketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -D_BPF_H_ $(FOURFA_USER_SRC) -o $(FOURFA_USER_BIN) $(LIBBPF_LDFLAGS) -lpcap


stable-run: stable-build
	@echo "=== Running StableSketch ==="
	@echo "Interface: $(IFACE)"
	@echo "Top-K: $(STABLE_TOPK)"
	@echo "Duration: $(STABLE_DURATION)s"
	@echo "Trace: $(STABLE_TRACE)"
	@echo ""
	sudo ./$(STABLE_USER_BIN) -i $(IFACE) -k $(STABLE_TOPK) -D $(STABLE_DURATION) -t $(STABLE_TRACE)

jigsaw-run: jigsaw-build jigsaw-setup
	@echo "=== Running Jigsaw ==="
	@echo "Interface: $(JIGSAW_IFACE)"
	@echo "Top-K: $(JIGSAW_TOPK)"
	@echo "Duration: $(JIGSAW_DURATION)s"
	@echo "Trace: $(JIGSAW_TRACE)"
	@echo ""
	sudo ./$(JIGSAW_USER_BIN) -i $(JIGSAW_IFACE) -o $(JIGSAW_PIN_DIR) -k $(JIGSAW_TOPK) -D $(JIGSAW_DURATION) -t $(JIGSAW_TRACE) $(JIGSAW_BPF_OBJ)

fourfa-run: fourfa-build
	@echo "=== Running 4FASketch ==="
	@echo "Interface: $(FOURFA_IFACE)"
	@echo "Top-K: $(FOURFA_TOPK)"
	@echo "Duration: $(FOURFA_DURATION)s"
	@echo "PCAP: $(FOURFA_PCAP)"
	@echo ""
	@echo ""
	sudo ./$(FOURFA_USER_BIN) -i $(FOURFA_IFACE) -k $(FOURFA_TOPK) -D $(FOURFA_DURATION) -t $(FOURFA_PCAP)

replay-stable:
	@echo "=== Replaying packets for StableSketch ==="
	@echo "Interface: $(STABLE_REPLAY_IFACE)"
	@echo "PCAP: $(STABLE_PCAP)"
	sudo tcpreplay --intf1=$(STABLE_REPLAY_IFACE) --topspeed $(STABLE_PCAP)

replay-jigsaw:
	@echo "=== Replaying packets for Jigsaw ==="
	@echo "Interface: $(JIGSAW_REPLAY_IFACE)"
	@echo "PCAP: $(JIGSAW_PCAP)"
	sudo tcpreplay --intf1=$(JIGSAW_REPLAY_IFACE) --topspeed $(JIGSAW_PCAP)

replay-fourfa:
	@echo "=== Replaying packets for 4FASketch ==="
	@echo "Interface: $(FOURFA_REPLAY_IFACE)"
	@echo "PCAP: $(FOURFA_PCAP)"
	sudo tcpreplay --intf1=$(FOURFA_REPLAY_IFACE) --topspeed $(FOURFA_PCAP)

test-stable: stable-build
	@echo "=== Running StableSketch automated test ==="
	@echo "Starting StableSketch in background..."
	@sudo ./$(STABLE_USER_BIN) -i $(STABLE_IFACE) -k $(STABLE_TOPK) -D $(STABLE_DURATION) -t $(STABLE_TRACE) > stable_test_output.log 2>&1 & echo $$! > /tmp/stable_sketch.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(STABLE_REPLAY_IFACE) --topspeed $(STABLE_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(STABLE_DURATION)
	@sleep 2
	@echo "Stopping StableSketch..."
	@sudo kill -INT $$(cat /tmp/stable_sketch.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== StableSketch Test Results ==="
	@cat stable_test_output.log | tr -d '\r'
	@rm -f /tmp/stable_sketch.pid

test-jigsaw: jigsaw-build jigsaw-setup
	@test -f $(JIGSAW_BPF_OBJ) || (echo "ERROR: $(JIGSAW_BPF_OBJ) not found!"; exit 1)
	@echo "=== Running Jigsaw automated test ==="
	@echo "Starting Jigsaw in background..."
	@sudo ./$(JIGSAW_USER_BIN) -i $(JIGSAW_IFACE) -o $(JIGSAW_PIN_DIR) -k $(JIGSAW_TOPK) -D $(JIGSAW_DURATION) -t $(JIGSAW_TRACE) $(JIGSAW_BPF_OBJ) > jigsaw_test_output.log 2>&1 & echo $$! > /tmp/jigsaw_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(JIGSAW_REPLAY_IFACE) --topspeed $(JIGSAW_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(JIGSAW_DURATION)
	@sleep 2
	@echo "Stopping Jigsaw..."
	@sudo kill -INT $$(cat /tmp/jigsaw_loader.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== Jigsaw Test Results ==="
	@cat jigsaw_test_output.log | tr -d '\r'
	@rm -f /tmp/jigsaw_loader.pid

test-fourfa: fourfa-build
	@echo "=== Running 4FASketch automated test ==="
	@echo "Starting 4FASketch in background..."
	sudo ./$(FOURFA_USER_BIN) -i $(FOURFA_IFACE) -k $(FOURFA_TOPK) -D $(FOURFA_DURATION) -t $(FOURFA_PCAP) > fourfa_test_output.log 2>&1 & echo $$! > /tmp/fourfa_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(FOURFA_REPLAY_IFACE) --topspeed $(FOURFA_PCAP) || true
	@echo "Waiting for 4FASketch auto-detection..."
	@sleep $(FOURFA_DURATION)
	@echo ""
	@echo "=== 4FASketch Test Results ==="
	@cat fourfa_test_output.log | tr -d '\r'
	@rm -f /tmp/fourfa_loader.pid

stop-xdp-stable:
	@echo "Detaching StableSketch XDP from $(IFACE)..."
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

stop-xdp-jigsaw:
	@echo "Detaching Jigsaw XDP from $(JIGSAW_IFACE)..."
	@sudo ip link set dev $(JIGSAW_IFACE) xdp off 2>/dev/null || true

stop-xdp-fourfa:
	@echo "Detaching 4FASketch XDP from $(FOURFA_IFACE)..."
	@sudo ip link set dev $(FOURFA_IFACE) xdp off 2>/dev/null || true

clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(STABLE_BPF_OBJ) $(STABLE_SKEL) $(STABLE_USER_BIN)
	rm -f $(JIGSAW_BPF_OBJ) $(JIGSAW_USER_BIN)
	rm -f $(FOURFA_BPF_OBJ) $(FOURFA_SKEL) $(FOURFA_USER_BIN)
	rm -f stable_test_output.log jigsaw_test_output.log fourfa_test_output.log
	rm -f /tmp/stable_sketch.pid /tmp/jigsaw_loader.pid /tmp/fourfa_loader.pid
	@echo "Cleaning Jigsaw pinned maps..."
	@sudo rm -f $(JIGSAW_PIN_DIR)/aux_map $(JIGSAW_PIN_DIR)/bucket_map $(JIGSAW_PIN_DIR)/xdp_stats_map 2>/dev/null || true
	@echo "Done"

clean-all: clean
	@echo "Removing vmlinux.h..."
	rm -f $(VMLINUX)
