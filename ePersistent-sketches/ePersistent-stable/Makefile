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
# PERSISTENT STABLE SKETCH Configuration
# ============================================================================
PERSISTENT_BPF_SRC := persistent_stable_sketch_ebpf.c
PERSISTENT_BPF_OBJ := persistent_stable_sketch_ebpf.o
PERSISTENT_SKEL := persistent_stable_sketch_ebpf.skel.h
PERSISTENT_USER_SRC := persistent_stable_sketch_user.c
PERSISTENT_USER_BIN := persistent_stable_sketch_user
PERSISTENT_COMMON := persistent_stable_sketch_common.h

# Persistent runtime parameters (can be overridden)
PERSISTENT_IFACE ?= veth-recv
PERSISTENT_TOPK ?= 50
PERSISTENT_DURATION ?= 10
PERSISTENT_TRACE ?= ../jigsaw_2.dat
PERSISTENT_PCAP ?= ../2.pcap
PERSISTENT_REPLAY_IFACE ?= veth-send
PERSISTENT_WINDOWS ?= 1600
PERSISTENT_THRESHOLD ?= 0.5

# ============================================================================
# STABLE SKETCH Configuration
# ============================================================================
STABLE_BPF_SRC := stable_sketch_ebpf.c
STABLE_BPF_OBJ := stable_sketch_ebpf.o
STABLE_SKEL := stable_sketch_ebpf.skel.h
STABLE_USER_SRC := stable_sketch_user.c
STABLE_USER_BIN := stable_sketch_user
STABLE_COMMON := stable_sketch_common.h

# StableSketch runtime parameters
STABLE_IFACE ?= veth-recv
STABLE_TOPK ?= 1000
STABLE_DURATION ?= 10
STABLE_TRACE ?= ../jigsaw_1.dat
STABLE_PCAP ?= ../1.pcap
STABLE_REPLAY_IFACE ?= veth-send

# ============================================================================
# JIGSAW Configuration
# ============================================================================
JIGSAW_BPF_SRC := jigsaw_xdp.c
JIGSAW_BPF_OBJ := jigsaw_xdp.o
JIGSAW_USER_SRC := jigsaw_loader.c
JIGSAW_USER_BIN := jigsaw_loader

# Jigsaw runtime parameters
JIGSAW_IFACE ?= veth0
JIGSAW_REPLAY_IFACE ?= veth1
JIGSAW_PIN_DIR ?= /sys/fs/bpf/jigsaw
JIGSAW_TOPK ?= 1000
JIGSAW_DURATION ?= 10
JIGSAW_TRACE ?= ./dats/jigsaw_2.dat
JIGSAW_PCAP ?= ./pcaps/2.pcap

# ============================================================================
# 2FASKETCH Configuration
# ============================================================================
TWOFA_BPF_SRC := twofa_sketch_ebpf.c
TWOFA_BPF_OBJ := twofa_sketch_ebpf.o
TWOFA_SKEL := twofa_sketch_ebpf.skel.h
TWOFA_USER_SRC := twofa_sketch_loader.c
TWOFA_USER_BIN := twofa_sketch_loader
TWOFA_COMMON := twofa_sketch_common.h

# 2FASketch runtime parameters
TWOFA_IFACE ?= veth-recv
TWOFA_REPLAY_IFACE ?= veth-send
TWOFA_DURATION ?= 10
TWOFA_TOPK ?= 1000
TWOFA_PCAP ?= ./packets_from_dat.pcap

# ============================================================================
# Common files
# ============================================================================
VMLINUX := vmlinux.h

# ============================================================================
# Main targets
# ============================================================================
.PHONY: all help clean clean-all vmlinux
.PHONY: stable jigsaw twofa persistent
.PHONY: stable-build jigsaw-build twofa-build persistent-build
.PHONY: stable-run jigsaw-run twofa-run persistent-run
.PHONY: test-stable test-jigsaw test-twofa test-persistent
.PHONY: replay-stable replay-jigsaw replay-twofa replay-persistent
.PHONY: stop-xdp-stable stop-xdp-jigsaw stop-xdp-twofa stop-xdp-persistent

all: help

help:
	@echo "=== Unified eBPF Sketch Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make stable         - Build StableSketch (Heavy Hitter)"
	@echo "  make persistent     - Build Persistent-StableSketch"
	@echo "  make jigsaw         - Build Jigsaw"
	@echo "  make twofa          - Build 2FASketch"
	@echo ""
	@echo "Run targets:"
	@echo "  make stable-run IFACE=<if>           - Run StableSketch"
	@echo "  make persistent-run IFACE=<if>       - Run Persistent-StableSketch"
	@echo "  make jigsaw-run IFACE=<if>           - Run Jigsaw"
	@echo "  make twofa-run IFACE=<if>            - Run 2FASketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-stable IFACE=<if>          - Full StableSketch test"
	@echo "  make test-persistent IFACE=<if>      - Full Persistent-StableSketch test"
	@echo "  make test-jigsaw IFACE=<if>          - Full Jigsaw test"
	@echo "  make test-twofa IFACE=<if>           - Full 2FASketch test"
	@echo ""
	@echo "Replay targets:"
	@echo "  make replay-stable IFACE=<if>        - Replay packets for StableSketch"
	@echo "  make replay-persistent IFACE=<if>    - Replay packets for Persistent"
	@echo "  make replay-jigsaw IFACE=<if>        - Replay packets for Jigsaw"
	@echo "  make replay-twofa IFACE=<if>         - Replay packets for 2FASketch"
	@echo ""
	@echo "Stop XDP:"
	@echo "  make stop-xdp-stable IFACE=<if>      - Detach StableSketch XDP"
	@echo "  make stop-xdp-persistent IFACE=<if>  - Detach Persistent XDP"
	@echo "  make stop-xdp-jigsaw IFACE=<if>      - Detach Jigsaw XDP"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean                           - Remove all build artifacts"
	@echo ""
	@echo "Persistent-StableSketch parameters:"
	@echo "  IFACE=$(PERSISTENT_IFACE)"
	@echo "  PERSISTENT_TOPK=$(PERSISTENT_TOPK)"
	@echo "  PERSISTENT_DURATION=$(PERSISTENT_DURATION)"
	@echo "  PERSISTENT_TRACE=$(PERSISTENT_TRACE)"
	@echo "  PERSISTENT_PCAP=$(PERSISTENT_PCAP)"
	@echo "  PERSISTENT_WINDOWS=$(PERSISTENT_WINDOWS)"
	@echo "  PERSISTENT_THRESHOLD=$(PERSISTENT_THRESHOLD)"
	@echo ""
	@echo "Examples:"
	@echo "  make persistent IFACE=veth-recv"
	@echo "  make test-persistent IFACE=veth-recv PERSISTENT_WINDOWS=800 PERSISTENT_THRESHOLD=0.5"

# ============================================================================
# VMLINUX generation
# ============================================================================
$(VMLINUX):
	@echo "Generating vmlinux.h..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

vmlinux: $(VMLINUX)

# ============================================================================
# PERSISTENT STABLE SKETCH BUILD
# ============================================================================
persistent: persistent-build

persistent-build: $(PERSISTENT_USER_BIN)
	@echo "=== Persistent-StableSketch built successfully ==="

$(PERSISTENT_BPF_OBJ): $(PERSISTENT_BPF_SRC) $(PERSISTENT_COMMON) $(VMLINUX)
	@echo "Compiling Persistent-StableSketch BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(PERSISTENT_BPF_SRC) -o $(PERSISTENT_BPF_OBJ)
	$(LLVM_STRIP) -g $(PERSISTENT_BPF_OBJ)

$(PERSISTENT_SKEL): $(PERSISTENT_BPF_OBJ)
	@echo "Generating Persistent-StableSketch skeleton..."
	$(BPFTOOL) gen skeleton $(PERSISTENT_BPF_OBJ) > $(PERSISTENT_SKEL)

$(PERSISTENT_USER_BIN): $(PERSISTENT_USER_SRC) $(PERSISTENT_SKEL) $(PERSISTENT_COMMON)
	@echo "Compiling Persistent-StableSketch userspace program..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(PERSISTENT_USER_SRC) -o $(PERSISTENT_USER_BIN) $(LIBBPF_LDFLAGS) -lm

# ============================================================================
# STABLE SKETCH BUILD
# ============================================================================
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

# ============================================================================
# JIGSAW BUILD
# ============================================================================
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

# ============================================================================
# 2FASKETCH BUILD 
# ============================================================================
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

# ============================================================================
# RUN TARGETS
# ============================================================================
persistent-run: persistent-build
	@echo "=== Running Persistent-StableSketch ==="
	@echo "Interface: $(PERSISTENT_IFACE)"
	@echo "Top-K: $(PERSISTENT_TOPK)"
	@echo "Duration: $(PERSISTENT_DURATION)s"
	@echo "Windows: $(PERSISTENT_WINDOWS)"
	@echo "Threshold: $(PERSISTENT_THRESHOLD)"
	@echo "Trace: $(PERSISTENT_TRACE)"
	@echo ""
	sudo ./$(PERSISTENT_USER_BIN) -i $(PERSISTENT_IFACE) -k $(PERSISTENT_TOPK) -D $(PERSISTENT_DURATION) -t $(PERSISTENT_TRACE) -w $(PERSISTENT_WINDOWS) -T $(PERSISTENT_THRESHOLD)

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
	sudo ./$(TWOFA_USER_BIN) -i $(TWOFA_IFACE) -k $(TWOFA_TOPK) -D $(TWOFA_DURATION) -t $(TWOFA_PCAP)

# ============================================================================
# REPLAY TARGETS
# ============================================================================
replay-persistent:
	@echo "=== Replaying packets for Persistent-StableSketch ==="
	@echo "Interface: $(PERSISTENT_REPLAY_IFACE)"
	@echo "PCAP: $(PERSISTENT_PCAP)"
	sudo tcpreplay --intf1=$(PERSISTENT_REPLAY_IFACE) --topspeed $(PERSISTENT_PCAP)

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

# ============================================================================
# AUTOMATED TEST TARGETS
# ============================================================================
test-persistent: persistent-build
	@echo "=== Running Persistent-StableSketch automated test ==="
	@echo "Starting Persistent-StableSketch in background..."
	@sudo ./$(PERSISTENT_USER_BIN) -i $(PERSISTENT_IFACE) -k $(PERSISTENT_TOPK) -D $(PERSISTENT_DURATION) -t $(PERSISTENT_TRACE) -w $(PERSISTENT_WINDOWS) -T $(PERSISTENT_THRESHOLD) > persistent_test_output.log 2>&1 & echo $$! > /tmp/persistent_sketch.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(PERSISTENT_REPLAY_IFACE) --topspeed $(PERSISTENT_PCAP) || true
	@echo "Waiting for collection to complete..."
	@sleep $(PERSISTENT_DURATION)
	@sleep 2
	@echo "Stopping Persistent-StableSketch..."
	@sudo kill -INT $$(cat /tmp/persistent_sketch.pid 2>/dev/null) 2>/dev/null || true
	@sleep 2
	@echo ""
	@echo "=== Persistent-StableSketch Test Results ==="
	@cat persistent_test_output.log | tr -d '\r'
	@rm -f /tmp/persistent_sketch.pid

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

# ============================================================================
# STOP XDP
# ============================================================================
stop-xdp-persistent:
	@echo "Detaching Persistent-StableSketch XDP from $(PERSISTENT_IFACE)..."
	@sudo ip link set dev $(PERSISTENT_IFACE) xdp off 2>/dev/null || true

stop-xdp-stable:
	@echo "Detaching StableSketch XDP from $(IFACE)..."
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

stop-xdp-jigsaw:
	@echo "Detaching Jigsaw XDP from $(JIGSAW_IFACE)..."
	@sudo ip link set dev $(JIGSAW_IFACE) xdp off 2>/dev/null || true

stop-xdp-twofa:
	@echo "Detaching 2FASketch XDP from $(TWOFA_IFACE)..."
	@sudo ip link set dev $(TWOFA_IFACE) xdp off 2>/dev/null || true

# ============================================================================
# CLEANUP
# ============================================================================
clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(PERSISTENT_BPF_OBJ) $(PERSISTENT_SKEL) $(PERSISTENT_USER_BIN)
	rm -f $(STABLE_BPF_OBJ) $(STABLE_SKEL) $(STABLE_USER_BIN)
	rm -f $(JIGSAW_BPF_OBJ) $(JIGSAW_USER_BIN)
	rm -f $(TWOFA_BPF_OBJ) $(TWOFA_SKEL) $(TWOFA_USER_BIN)
	rm -f persistent_test_output.log stable_test_output.log jigsaw_test_output.log twofa_test_output.log
	rm -f /tmp/persistent_sketch.pid /tmp/stable_sketch.pid /tmp/jigsaw_loader.pid /tmp/twofa_loader.pid
	@echo "Cleaning Jigsaw pinned maps..."
	@sudo rm -f $(JIGSAW_PIN_DIR)/aux_map $(JIGSAW_PIN_DIR)/bucket_map $(JIGSAW_PIN_DIR)/xdp_stats_map 2>/dev/null || true
	@echo "Done"

clean-all: clean
	@echo "Removing vmlinux.h..."
	rm -f $(VMLINUX)