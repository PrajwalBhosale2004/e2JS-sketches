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


THREEFA_BPF_SRC := threefa_sketch_ebpf.c
THREEFA_BPF_OBJ := threefa_sketch_ebpf.o
THREEFA_SKEL := threefa_sketch_ebpf.skel.h
THREEFA_USER_SRC := threefa_sketch_loader.c
THREEFA_USER_BIN := threefa_sketch_loader
THREEFA_COMMON := threefa_sketch_common.h

THREEFA_IFACE ?= veth-recv
THREEFA_REPLAY_IFACE ?= veth-send
THREEFA_DURATION ?= 10
THREEFA_TOPK ?= 10000
THREEFA_PCAP ?= ./1.pcap


VMLINUX := vmlinux.h

.PHONY: all help clean clean-all vmlinux
.PHONY: stable jigsaw threefa
.PHONY: stable-build jigsaw-build threefa-build
.PHONY: stable-run jigsaw-run threefa-run
.PHONY: test-stable test-jigsaw test-threefa
.PHONY: replay-stable replay-jigsaw replay-threefa
.PHONY: stop-xdp-stable stop-xdp-jigsaw stop-xdp-threefa

all: help

help:
	@echo "=== Unified eBPF Sketch Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make stable         - Build StableSketch"
	@echo "  make jigsaw         - Build Jigsaw"
	@echo "  make threefa        - Build 3FASketch"
	@echo "  make all           - Show this help"
	@echo ""
	@echo "Run targets:"
	@echo "  make stable-run IFACE=<if>           - Run StableSketch (blocking)"
	@echo "  make jigsaw-run IFACE=<if>           - Run Jigsaw (blocking)"
	@echo "  make threefa-run IFACE=<if>          - Run 3FASketch (blocking)"
	@echo "  make replay-stable IFACE=<if>        - Replay packets for StableSketch"
	@echo "  make replay-jigsaw IFACE=<if>        - Replay packets for Jigsaw"
	@echo "  make replay-threefa IFACE=<if>       - Replay packets for 3FASketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-stable IFACE=<if>          - Full StableSketch test"
	@echo "  make test-jigsaw IFACE=<if>          - Full Jigsaw test"
	@echo "  make test-threefa IFACE=<if>         - Full 3FASketch test"
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
	@echo "3FASketch parameters (override with VAR=value):"
	@echo "  IFACE=$(THREEFA_IFACE)"
	@echo "  THREEFA_TOPK=$(THREEFA_TOPK)"
	@echo "  THREEFA_DURATION=$(THREEFA_DURATION)"
	@echo "  THREEFA_PCAP=$(THREEFA_PCAP)"
	@echo "  THREEFA_REPLAY_IFACE=$(THREEFA_REPLAY_IFACE)"
	@echo ""
	@echo "Examples:"
	@echo "  make stable IFACE=veth-recv"
	@echo "  make test-stable IFACE=veth-recv STABLE_TOPK=500"
	@echo "  make jigsaw IFACE=veth0"
	@echo "  make test-jigsaw IFACE=veth0 JIGSAW_DURATION=5"
	@echo "  make threefa IFACE=veth-recv"
	@echo "  sudo make test-threefa IFACE=veth-recv THREEFA_TOPK=500"


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


threefa: threefa-build

threefa-build: $(THREEFA_USER_BIN)
	@echo "=== 3FASketch built successfully ==="

$(THREEFA_BPF_OBJ): $(THREEFA_BPF_SRC) $(THREEFA_COMMON)
	@echo "Compiling 3FASketch BPF program"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(THREEFA_BPF_SRC) -o $(THREEFA_BPF_OBJ)

$(THREEFA_SKEL): $(THREEFA_BPF_OBJ)
	@echo "Generating 3FASketch skeleton..."
	$(BPFTOOL) gen skeleton $(THREEFA_BPF_OBJ) > $(THREEFA_SKEL)

$(THREEFA_USER_BIN): $(THREEFA_USER_SRC) $(THREEFA_SKEL) $(THREEFA_COMMON)
	@echo "Compiling 3FASketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -D_BPF_H_ $(THREEFA_USER_SRC) -o $(THREEFA_USER_BIN) $(LIBBPF_LDFLAGS) -lpcap


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

threefa-run: threefa-build
	@echo "=== Running 3FASketch ==="
	@echo "Interface: $(THREEFA_IFACE)"
	@echo "Top-K: $(THREEFA_TOPK)"
	@echo "Duration: $(THREEFA_DURATION)s"
	@echo "PCAP: $(THREEFA_PCAP)"
	@echo ""
	@echo ""
	sudo ./$(THREEFA_USER_BIN) -i $(THREEFA_IFACE) -k $(THREEFA_TOPK) -D $(THREEFA_DURATION) -t $(THREEFA_PCAP)

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

replay-threefa:
	@echo "=== Replaying packets for 3FASketch ==="
	@echo "Interface: $(THREEFA_REPLAY_IFACE)"
	@echo "PCAP: $(THREEFA_PCAP)"
	sudo tcpreplay --intf1=$(THREEFA_REPLAY_IFACE) --topspeed $(THREEFA_PCAP)


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

test-threefa: threefa-build
	@echo "=== Running 3FASketch automated test ==="
	@echo "Starting 3FASketch in background..."
	sudo ./$(THREEFA_USER_BIN) -i $(THREEFA_IFACE) -k $(THREEFA_TOPK) -D $(THREEFA_DURATION) -t $(THREEFA_PCAP) > threefa_test_output.log 2>&1 & echo $$! > /tmp/threefa_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(THREEFA_REPLAY_IFACE) --topspeed $(THREEFA_PCAP) || true
	@echo "Waiting for 3FASketch auto-detection..."
	@sleep $(THREEFA_DURATION)
	@echo ""
	@echo "=== 3FASketch Test Results ==="
	@cat threefa_test_output.log | tr -d '\r'
	@rm -f /tmp/threefa_loader.pid


stop-xdp-stable:
	@echo "Detaching StableSketch XDP from $(IFACE)..."
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

stop-xdp-jigsaw:
	@echo "Detaching Jigsaw XDP from $(JIGSAW_IFACE)..."
	@sudo ip link set dev $(JIGSAW_IFACE) xdp off 2>/dev/null || true

stop-xdp-threefa:
	@echo "Detaching 3FASketch XDP from $(THREEFA_IFACE)..."
	@sudo ip link set dev $(THREEFA_IFACE) xdp off 2>/dev/null || true


clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(STABLE_BPF_OBJ) $(STABLE_SKEL) $(STABLE_USER_BIN)
	rm -f $(JIGSAW_BPF_OBJ) $(JIGSAW_USER_BIN)
	rm -f $(THREEFA_BPF_OBJ) $(THREEFA_SKEL) $(THREEFA_USER_BIN)
	rm -f stable_test_output.log jigsaw_test_output.log threefa_test_output.log
	rm -f /tmp/stable_sketch.pid /tmp/jigsaw_loader.pid /tmp/threefa_loader.pid
	@echo "Cleaning Jigsaw pinned maps..."
	@sudo rm -f $(JIGSAW_PIN_DIR)/aux_map $(JIGSAW_PIN_DIR)/bucket_map $(JIGSAW_PIN_DIR)/xdp_stats_map 2>/dev/null || true
	@echo "Done"

clean-all: clean
	@echo "Removing vmlinux.h..."
	rm -f $(VMLINUX)
