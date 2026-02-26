BPF_CLANG ?= clang
CC ?= gcc

LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -O2 -g -target bpf -I. -D__TARGET_ARCH_$(ARCH)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo -I/usr/include)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)


STABLE_BPF_SRC := r_stable_sketch_ebpf.c
STABLE_BPF_OBJ := r_stable_sketch_ebpf.o
STABLE_SKEL := r_stable_sketch_ebpf.skel.h
STABLE_USER_SRC := r_stable_sketch_user.c
STABLE_USER_BIN := r_stable_sketch_user
STABLE_COMMON := r_stable_sketch_common.h


STABLE_IFACE ?= veth-recv
STABLE_TOPK ?= 1000
STABLE_DURATION ?= 10
STABLE_TRACE ?= ../jigsaw_1.dat
STABLE_PCAP ?= ../1.pcap
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


TWOFA_BPF_SRC := twofa_sketch_ebpf.c
TWOFA_BPF_OBJ := twofa_sketch_ebpf.o
TWOFA_SKEL := twofa_sketch_ebpf.skel.h
TWOFA_USER_SRC := twofa_sketch_loader.c
TWOFA_USER_BIN := twofa_sketch_loader
TWOFA_COMMON := twofa_sketch_common.h


TWOFA_IFACE ?= veth-recv
TWOFA_REPLAY_IFACE ?= veth-send
TWOFA_DURATION ?= 10
TWOFA_TOPK ?= 1000
TWOFA_PCAP ?= ./packets_from_dat.pcap

VMLINUX := vmlinux.h

.PHONY: all help clean clean-all vmlinux
.PHONY: stable jigsaw twofa
.PHONY: stable-build jigsaw-build twofa-build
.PHONY: stable-run jigsaw-run twofa-run
.PHONY: test-stable test-jigsaw test-twofa
.PHONY: replay-stable replay-jigsaw replay-twofa
.PHONY: stop-xdp-stable stop-xdp-jigsaw stop-xdp-twofa

all: help

help:
	@echo "=== Unified eBPF Sketch Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make stable         - Build StableSketch"
	@echo "  make jigsaw         - Build Jigsaw"
	@echo "  make twofa          - Build 2FASketch"
	@echo "  make all           - Show this help"
	@echo ""
	@echo "Run targets:"
	@echo "  make stable-run IFACE=<if>           - Run StableSketch (blocking)"
	@echo "  make jigsaw-run IFACE=<if>           - Run Jigsaw (blocking)"
	@echo "  make twofa-run IFACE=<if>            - Run 2FASketch (blocking)"
	@echo "  make replay-stable IFACE=<if>        - Replay packets for StableSketch"
	@echo "  make replay-jigsaw IFACE=<if>        - Replay packets for Jigsaw"
	@echo "  make replay-twofa IFACE=<if>         - Replay packets for 2FASketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-stable IFACE=<if>          - Full StableSketch test"
	@echo "  make test-jigsaw IFACE=<if>          - Full Jigsaw test"
	@echo "  make test-twofa IFACE=<if>           - Full 2FASketch test"
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
	@echo "2FASketch parameters (override with VAR=value):"
	@echo "  IFACE=$(TWOFA_IFACE)"
	@echo "  TWOFA_TOPK=$(TWOFA_TOPK)"
	@echo "  TWOFA_DURATION=$(TWOFA_DURATION)"
	@echo "  TWOFA_PCAP=$(TWOFA_PCAP)"
	@echo "  TWOFA_REPLAY_IFACE=$(TWOFA_REPLAY_IFACE)"
	@echo ""
	@echo "Examples:"
	@echo "  make stable IFACE=veth-recv"
	@echo "  make test-stable IFACE=veth-recv STABLE_TOPK=500"
	@echo "  make jigsaw IFACE=veth0"
	@echo "  make test-jigsaw IFACE=veth0 JIGSAW_DURATION=5"
	@echo "  make twofa IFACE=veth-recv"
	@echo "  sudo make test-twofa IFACE=veth-recv TWOFA_TOPK=500"

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




twofa: twofa-build

twofa-build: $(TWOFA_USER_BIN)
	@echo "=== 2FASketch built successfully ==="

$(TWOFA_BPF_OBJ): $(TWOFA_BPF_SRC) $(TWOFA_COMMON)
	@echo "Compiling 2FASketch BPF program"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(TWOFA_BPF_SRC) -o $(TWOFA_BPF_OBJ)

$(TWOFA_SKEL): $(TWOFA_BPF_OBJ)
	@echo "Generating 2FASketch skeleton..."
	$(BPFTOOL) gen skeleton $(TWOFA_BPF_OBJ) > $(TWOFA_SKEL)

$(TWOFA_USER_BIN): $(TWOFA_USER_SRC) $(TWOFA_SKEL) $(TWOFA_COMMON)
	@echo "Compiling 2FASketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -D_BPF_H_ $(TWOFA_USER_SRC) -o $(TWOFA_USER_BIN) $(LIBBPF_LDFLAGS) -lpcap


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

twofa-run: twofa-build
	@echo "=== Running 2FASketch ==="
	@echo "Interface: $(TWOFA_IFACE)"
	@echo "Top-K: $(TWOFA_TOPK)"
	@echo "Duration: $(TWOFA_DURATION)s"
	@echo "PCAP: $(TWOFA_PCAP)"
	@echo ""
	@echo ""
	sudo ./$(TWOFA_USER_BIN) -i $(TWOFA_IFACE) -k $(TWOFA_TOPK) -D $(TWOFA_DURATION) -t $(TWOFA_PCAP)

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

replay-twofa:
	@echo "=== Replaying packets for 2FASketch ==="
	@echo "Interface: $(TWOFA_REPLAY_IFACE)"
	@echo "PCAP: $(TWOFA_PCAP)"
	sudo tcpreplay --intf1=$(TWOFA_REPLAY_IFACE) --topspeed $(TWOFA_PCAP)


test-stable: stable-build
	@echo "=== Running StableSketch automated test ==="
	@echo "Starting StableSketch in background..."
	@sudo ./$(STABLE_USER_BIN) -i $(STABLE_IFACE) -k $(STABLE_TOPK) -D $(STABLE_DURATION) -t $(STABLE_TRACE) > stable_test_output.log 2>&1 & echo $$! > /tmp/r_stable_sketch.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(STABLE_REPLAY_IFACE) --topspeed $(STABLE_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(STABLE_DURATION)
	@sleep 2
	@echo "Stopping StableSketch..."
	@sudo kill -INT $$(cat /tmp/r_stable_sketch.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== StableSketch Test Results ==="
	@cat stable_test_output.log | tr -d '\r'
	@rm -f /tmp/r_stable_sketch.pid

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

test-twofa: twofa-build
	@echo "=== Running 2FASketch automated test ==="
	@echo "Starting 2FASketch in background..."
	sudo ./$(TWOFA_USER_BIN) -i $(TWOFA_IFACE) -k $(TWOFA_TOPK) -D $(TWOFA_DURATION) -t $(TWOFA_PCAP) > twofa_test_output.log 2>&1 & echo $$! > /tmp/twofa_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@tcpreplay --intf1=$(TWOFA_REPLAY_IFACE) --topspeed $(TWOFA_PCAP) || true
	@echo "Waiting for 2FASketch auto-detection..."
	@sleep $(TWOFA_DURATION)
	@echo ""
	@echo "=== 2FASketch Test Results ==="
	@cat twofa_test_output.log | tr -d '\r'
	@rm -f /tmp/twofa_loader.pid


stop-xdp-stable:
	@echo "Detaching StableSketch XDP from $(IFACE)..."
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

stop-xdp-jigsaw:
	@echo "Detaching Jigsaw XDP from $(JIGSAW_IFACE)..."
	@sudo ip link set dev $(JIGSAW_IFACE) xdp off 2>/dev/null || true

stop-xdp-twofa:
	@echo "Detaching 2FASketch XDP from $(TWOFA_IFACE)..."
	@sudo ip link set dev $(TWOFA_IFACE) xdp off 2>/dev/null || true


clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(STABLE_BPF_OBJ) $(STABLE_SKEL) $(STABLE_USER_BIN)
	rm -f $(JIGSAW_BPF_OBJ) $(JIGSAW_USER_BIN)
	rm -f $(TWOFA_BPF_OBJ) $(TWOFA_SKEL) $(TWOFA_USER_BIN)
	rm -f stable_test_output.log jigsaw_test_output.log
	rm -f /tmp/r_stable_sketch.pid /tmp/jigsaw_loader.pid
	@echo "Cleaning Jigsaw pinned maps..."
	@sudo rm -f $(JIGSAW_PIN_DIR)/aux_map $(JIGSAW_PIN_DIR)/bucket_map $(JIGSAW_PIN_DIR)/xdp_stats_map 2>/dev/null || true
	@echo "Done"

clean-all: clean
	@echo "Removing vmlinux.h..."
	rm -f $(VMLINUX)