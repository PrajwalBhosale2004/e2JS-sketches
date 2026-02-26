BPF_CLANG ?= clang
CC ?= gcc

LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

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




TWOFA_BPF_SRC := twofa_sketch_ebpf.c
TWOFA_BPF_OBJ := twofa_sketch_ebpf.o
TWOFA_SKEL := twofa_sketch_ebpf.skel.h
TWOFA_USER_SRC := twofa_sketch_loader.c
TWOFA_USER_BIN := twofa_sketch_loader
TWOFA_COMMON := twofa_sketch_common.h


TWOFA_IFACE ?= veth-recv
TWOFA_REPLAY_IFACE ?= veth-send
TWOFA_DURATION ?= 15
TWOFA_TOPK ?= 100
TWOFA_PCAP ?= ./packets_from_dat.pcap


ONEFA_BPF_SRC := onefa_sketch_ebpf.c
ONEFA_BPF_OBJ := onefa_sketch_ebpf.o
ONEFA_SKEL := onefa_sketch_ebpf.skel.h
ONEFA_USER_SRC := onefa_sketch_loader.c
ONEFA_USER_BIN := onefa_sketch_loader
ONEFA_COMMON := onefa_sketch_common.h


ONEFA_IFACE ?= veth-recv
ONEFA_REPLAY_IFACE ?= veth-send
ONEFA_DURATION ?= 15
ONEFA_TOPK ?= 1000
ONEFA_PCAP ?= ./packets_from_dat.pcap


ELASTIC_BPF_SRC := elastic_sketch_ebpf.c
ELASTIC_BPF_OBJ := elastic_sketch_ebpf.o
ELASTIC_SKEL := elastic_sketch_ebpf.skel.h
ELASTIC_USER_SRC := elastic_sketch_loader.c
ELASTIC_USER_BIN := elastic_sketch_loader
ELASTIC_COMMON := elastic_sketch_common.h


ELASTIC_IFACE ?= veth-recv
ELASTIC_REPLAY_IFACE ?= veth-send
ELASTIC_DURATION ?= 15
ELASTIC_TOPK ?= 800
ELASTIC_PCAP ?= ./packets_from_dat.pcap


VMLINUX := vmlinux.h


.PHONY: all help clean clean-all vmlinux
.PHONY: stable jigsaw twofa onefa elastic
.PHONY: stable-build jigsaw-build twofa-build onefa-build elastic-build
.PHONY: stable-run jigsaw-run twofa-run onefa-run elastic-run
.PHONY: test-stable test-jigsaw test-twofa test-onefa test-elastic
.PHONY: replay-stable replay-jigsaw replay-twofa replay-onefa replay-elastic
.PHONY: stop-xdp-stable stop-xdp-jigsaw stop-xdp-twofa stop-xdp-onefa stop-xdp-elastic

all: help

help:
	@echo "=== Unified eBPF Sketch Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make stable         - Build StableSketch"
	@echo "  make jigsaw         - Build Jigsaw"
	@echo "  make twofa          - Build 2FASketch"
	@echo "  make onefa          - Build 1FASketch"
	@echo "  make elastic        - Build ElasticSketch"
	@echo "  make all            - Show this help"
	@echo ""
	@echo "Run targets:"
	@echo "  make stable-run IFACE=<if>           - Run StableSketch (blocking)"
	@echo "  make jigsaw-run IFACE=<if>           - Run Jigsaw (blocking)"
	@echo "  make twofa-run IFACE=<if>            - Run 2FASketch (blocking)"
	@echo "  make onefa-run IFACE=<if>            - Run 1FASketch (blocking)"
	@echo "  make elastic-run IFACE=<if>          - Run ElasticSketch (blocking)"
	@echo "  make replay-stable IFACE=<if>        - Replay packets for StableSketch"
	@echo "  make replay-jigsaw IFACE=<if>        - Replay packets for Jigsaw"
	@echo "  make replay-twofa IFACE=<if>         - Replay packets for 2FASketch"
	@echo "  make replay-onefa IFACE=<if>         - Replay packets for 1FASketch"
	@echo "  make replay-elastic IFACE=<if>       - Replay packets for ElasticSketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-stable IFACE=<if>          - Full StableSketch test"
	@echo "  make test-jigsaw IFACE=<if>          - Full Jigsaw test"
	@echo "  make test-twofa IFACE=<if>           - Full 2FASketch test"
	@echo "  make test-onefa IFACE=<if>           - Full 1FASketch test"
	@echo "  make test-elastic IFACE=<if>         - Full ElasticSketch test"
	@echo ""
	@echo "Utility targets:"
	@echo "  make setup-veth                      - Setup veth pair (veth-send/veth-recv)"
	@echo "  make teardown-veth                   - Remove veth pair"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                           - Remove all build artifacts"
	@echo "  make stop-xdp-stable IFACE=<if>      - Detach StableSketch XDP"
	@echo "  make stop-xdp-jigsaw IFACE=<if>      - Detach Jigsaw XDP"
	@echo "  make stop-xdp-twofa IFACE=<if>       - Detach 2FASketch XDP"
	@echo "  make stop-xdp-onefa IFACE=<if>       - Detach 1FASketch XDP"
	@echo "  make stop-xdp-elastic IFACE=<if>     - Detach ElasticSketch XDP"
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
	@echo "=== Unified eBPF Sketch Makefile ==="
	@echo ""
	@echo "Build targets:"
	@echo "  make stable         - Build StableSketch"
	@echo "  make jigsaw         - Build Jigsaw"
	@echo "  make twofa          - Build 2FASketch"
	@echo "  make onefa          - Build 1FASketch"
	@echo "  make elastic        - Build ElasticSketch"
	@echo "  make all            - Show this help"
	@echo ""
	@echo "Run targets:"
	@echo "  make stable-run IFACE=<if>           - Run StableSketch (blocking)"
	@echo "  make jigsaw-run IFACE=<if>           - Run Jigsaw (blocking)"
	@echo "  make twofa-run IFACE=<if>            - Run 2FASketch (blocking)"
	@echo "  make onefa-run IFACE=<if>            - Run 1FASketch (blocking)"
	@echo "  make elastic-run IFACE=<if>          - Run ElasticSketch (blocking)"
	@echo "  make replay-stable IFACE=<if>        - Replay packets for StableSketch"
	@echo "  make replay-jigsaw IFACE=<if>        - Replay packets for Jigsaw"
	@echo "  make replay-twofa IFACE=<if>         - Replay packets for 2FASketch"
	@echo "  make replay-onefa IFACE=<if>         - Replay packets for 1FASketch"
	@echo "  make replay-elastic IFACE=<if>       - Replay packets for ElasticSketch"
	@echo ""
	@echo "Test targets (automated):"
	@echo "  make test-stable IFACE=<if>          - Full StableSketch test"
	@echo "  make test-jigsaw IFACE=<if>          - Full Jigsaw test"
	@echo "  make test-twofa IFACE=<if>           - Full 2FASketch test"
	@echo "  make test-onefa IFACE=<if>           - Full 1FASketch test"
	@echo "  make test-elastic IFACE=<if>         - Full ElasticSketch test"
	@echo ""
	@echo "Utility targets:"
	@echo "  make setup-veth                      - Setup veth pair (veth-send/veth-recv)"
	@echo "  make teardown-veth                   - Remove veth pair"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  make clean                           - Remove all build artifacts"
	@echo "  make stop-xdp-stable IFACE=<if>      - Detach StableSketch XDP"
	@echo "  make stop-xdp-jigsaw IFACE=<if>      - Detach Jigsaw XDP"
	@echo "  make stop-xdp-twofa IFACE=<if>       - Detach 2FASketch XDP"
	@echo "  make stop-xdp-onefa IFACE=<if>       - Detach 1FASketch XDP"
	@echo "  make stop-xdp-elastic IFACE=<if>     - Detach ElasticSketch XDP"
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
	@echo "1FASketch parameters (override with VAR=value):"
	@echo "  IFACE=$(ONEFA_IFACE)"
	@echo "  ONEFA_TOPK=$(ONEFA_TOPK)"
	@echo "  ONEFA_DURATION=$(ONEFA_DURATION)"
	@echo "  ONEFA_PCAP=$(ONEFA_PCAP)"
	@echo "  ONEFA_REPLAY_IFACE=$(ONEFA_REPLAY_IFACE)"
	@echo "1FASketch parameters (override with VAR=value):"
	@echo "  IFACE=$(ONEFA_IFACE)"
	@echo "  ONEFA_TOPK=$(ONEFA_TOPK)"
	@echo "  ONEFA_DURATION=$(ONEFA_DURATION)"
	@echo "  ONEFA_PCAP=$(ONEFA_PCAP)"
	@echo "  ONEFA_REPLAY_IFACE=$(ONEFA_REPLAY_IFACE)"
	@echo ""
	@echo "ElasticSketch parameters (override with VAR=value):"
	@echo "  IFACE=$(ELASTIC_IFACE)"
	@echo "  ELASTIC_TOPK=$(ELASTIC_TOPK)"
	@echo "  ELASTIC_DURATION=$(ELASTIC_DURATION)"
	@echo "  ELASTIC_PCAP=$(ELASTIC_PCAP)"
	@echo "  ELASTIC_REPLAY_IFACE=$(ELASTIC_REPLAY_IFACE)"
	@echo "ElasticSketch parameters (override with VAR=value):"
	@echo "  IFACE=$(ELASTIC_IFACE)"
	@echo "  ELASTIC_TOPK=$(ELASTIC_TOPK)"
	@echo "  ELASTIC_DURATION=$(ELASTIC_DURATION)"
	@echo "  ELASTIC_PCAP=$(ELASTIC_PCAP)"
	@echo "  ELASTIC_REPLAY_IFACE=$(ELASTIC_REPLAY_IFACE)"
	@echo ""
	@echo "Examples:"
	@echo "  make stable IFACE=veth-recv"
	@echo "  make test-stable IFACE=veth-recv STABLE_TOPK=500"
	@echo "  make jigsaw IFACE=veth0"
	@echo "  make test-jigsaw IFACE=veth0 JIGSAW_DURATION=5"
	@echo "  make twofa IFACE=veth-recv"
	@echo "  sudo make test-twofa IFACE=veth-recv TWOFA_TOPK=500"
	@echo "  make onefa IFACE=veth-recv"
	@echo "  sudo make test-onefa IFACE=veth-recv ONEFA_TOPK=500"
	@echo "  make elastic IFACE=veth-recv"
	@echo "  sudo make test-elastic IFACE=veth-recv ELASTIC_TOPK=500"

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




onefa: onefa-build

onefa-build: $(ONEFA_USER_BIN)
	@echo "=== 1FASketch built successfully ==="

$(ONEFA_BPF_OBJ): $(ONEFA_BPF_SRC) $(ONEFA_COMMON)
	@echo "Compiling 1FASketch BPF program"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(ONEFA_BPF_SRC) -o $(ONEFA_BPF_OBJ)

$(ONEFA_SKEL): $(ONEFA_BPF_OBJ)
	@echo "Generating 1FASketch skeleton..."
	$(BPFTOOL) gen skeleton $(ONEFA_BPF_OBJ) > $(ONEFA_SKEL)

$(ONEFA_USER_BIN): $(ONEFA_USER_SRC) $(ONEFA_SKEL) $(ONEFA_COMMON)
	@echo "Compiling 1FASketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -D_BPF_H_ $(ONEFA_USER_SRC) -o $(ONEFA_USER_BIN) $(LIBBPF_LDFLAGS) -lpcap




elastic: elastic-build

elastic-build: $(ELASTIC_USER_BIN)
	@echo "=== ElasticSketch built successfully ==="

$(ELASTIC_BPF_OBJ): $(ELASTIC_BPF_SRC) $(ELASTIC_COMMON) $(VMLINUX)
	@echo "Compiling ElasticSketch BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(ELASTIC_BPF_SRC) -o $(ELASTIC_BPF_OBJ)
	$(LLVM_STRIP) -g $(ELASTIC_BPF_OBJ)

$(ELASTIC_SKEL): $(ELASTIC_BPF_OBJ)
	@echo "Generating ElasticSketch skeleton..."
	$(BPFTOOL) gen skeleton $(ELASTIC_BPF_OBJ) > $(ELASTIC_SKEL)

$(ELASTIC_USER_BIN): $(ELASTIC_USER_SRC) $(ELASTIC_SKEL) $(ELASTIC_COMMON)
	@echo "Compiling ElasticSketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -D_BPF_H_ $(ELASTIC_USER_SRC) -o $(ELASTIC_USER_BIN) $(LIBBPF_LDFLAGS) -lpcap




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

onefa-run: onefa-build
	@echo "=== Running 1FASketch ==="
	@echo "Interface: $(ONEFA_IFACE)"
	@echo "Top-K: $(ONEFA_TOPK)"
	@echo "Duration: $(ONEFA_DURATION)s"
	@echo "PCAP: $(ONEFA_PCAP)"
	@echo ""
	@echo ""
	sudo ./$(ONEFA_USER_BIN) -i $(ONEFA_IFACE) -k $(ONEFA_TOPK) -D $(ONEFA_DURATION) -t $(ONEFA_PCAP)

elastic-run: elastic-build
	@echo "=== Running ElasticSketch ==="
	@echo "Interface: $(ELASTIC_IFACE)"
	@echo "Top-K: $(ELASTIC_TOPK)"
	@echo "Duration: $(ELASTIC_DURATION)s"
	@echo "PCAP: $(ELASTIC_PCAP)"
	@echo ""
	sudo ./$(ELASTIC_USER_BIN) -i $(ELASTIC_IFACE) -k $(ELASTIC_TOPK) -D $(ELASTIC_DURATION) -t $(ELASTIC_PCAP)




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

replay-onefa:
	@echo "=== Replaying packets for 1FASketch ==="
	@echo "Interface: $(ONEFA_REPLAY_IFACE)"
	@echo "PCAP: $(ONEFA_PCAP)"
	sudo tcpreplay --intf1=$(ONEFA_REPLAY_IFACE) --topspeed $(ONEFA_PCAP)

replay-elastic:
	@echo "=== Replaying packets for ElasticSketch ==="
	@echo "Interface: $(ELASTIC_REPLAY_IFACE)"
	@echo "PCAP: $(ELASTIC_PCAP)"
	sudo tcpreplay --intf1=$(ELASTIC_REPLAY_IFACE) --topspeed $(ELASTIC_PCAP)




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
	@sudo tcpreplay --intf1=$(TWOFA_REPLAY_IFACE) --topspeed $(TWOFA_PCAP) || true
	@echo "Waiting for 2FASketch auto-detection..."
	@sleep $(TWOFA_DURATION)
	@echo ""
	@echo "=== 2FASketch Test Results ==="
	@cat twofa_test_output.log | tr -d '\r'
	@rm -f /tmp/twofa_loader.pid

test-onefa: onefa-build
	@echo "=== Running 1FASketch automated test ==="
	@echo "Starting 1FASketch in background..."
	sudo ./$(ONEFA_USER_BIN) -i $(ONEFA_IFACE) -k $(ONEFA_TOPK) -D $(ONEFA_DURATION) -t $(ONEFA_PCAP) > onefa_test_output.log 2>&1 & echo $$! > /tmp/onefa_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(ONEFA_REPLAY_IFACE) --topspeed $(ONEFA_PCAP) || true
	@echo "Waiting for 1FASketch auto-detection..."
	@sleep $(ONEFA_DURATION)
	@echo ""
	@echo "=== 1FASketch Test Results ==="
	@cat onefa_test_output.log | tr -d '\r'
	@rm -f /tmp/onefa_loader.pid

test-elastic: elastic-build
	@echo "=== Running ElasticSketch automated test ==="
	@echo "Starting ElasticSketch in background..."
	sudo ./$(ELASTIC_USER_BIN) -i $(ELASTIC_IFACE) -k $(ELASTIC_TOPK) -D $(ELASTIC_DURATION) -t $(ELASTIC_PCAP) > elastic_test_output.log 2>&1 & echo $$! > /tmp/elastic_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(ELASTIC_REPLAY_IFACE) --topspeed $(ELASTIC_PCAP) || true
	@echo "Waiting for ElasticSketch collection..."
	@sleep $(ELASTIC_DURATION)
	@sleep 2
	@echo ""
	@echo "=== ElasticSketch Test Results ==="
	@cat elastic_test_output.log | tr -d '\r'
	@rm -f /tmp/elastic_loader.pid




stop-xdp-stable:
	@echo "Detaching StableSketch XDP from $(IFACE)..."
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

stop-xdp-jigsaw:
	@echo "Detaching Jigsaw XDP from $(JIGSAW_IFACE)..."
	@sudo ip link set dev $(JIGSAW_IFACE) xdp off 2>/dev/null || true

stop-xdp-twofa:
	@echo "Detaching 2FASketch XDP from $(TWOFA_IFACE)..."
	@sudo ip link set dev $(TWOFA_IFACE) xdp off 2>/dev/null || true

stop-xdp-onefa:
	@echo "Detaching 1FASketch XDP from $(ONEFA_IFACE)..."
	@sudo ip link set dev $(ONEFA_IFACE) xdp off 2>/dev/null || true

stop-xdp-elastic:
	@echo "Detaching ElasticSketch XDP from $(ELASTIC_IFACE)..."
	@sudo ip link set dev $(ELASTIC_IFACE) xdp off 2>/dev/null || true




	@echo "  make stable IFACE=veth-recv"
	@echo "  make test-stable IFACE=veth-recv STABLE_TOPK=500"
	@echo "  make jigsaw IFACE=veth0"
	@echo "  make test-jigsaw IFACE=veth0 JIGSAW_DURATION=5"
	@echo "  make twofa IFACE=veth-recv"
	@echo "  sudo make test-twofa IFACE=veth-recv TWOFA_TOPK=500"
	@echo "  make onefa IFACE=veth-recv"
	@echo "  sudo make test-onefa IFACE=veth-recv ONEFA_TOPK=500"
	@echo "  make elastic IFACE=veth-recv"
	@echo "  sudo make test-elastic IFACE=veth-recv ELASTIC_TOPK=500"




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


onefa: onefa-build

onefa-build: $(ONEFA_USER_BIN)
	@echo "=== 1FASketch built successfully ==="

$(ONEFA_BPF_OBJ): $(ONEFA_BPF_SRC) $(ONEFA_COMMON)
	@echo "Compiling 1FASketch BPF program"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(ONEFA_BPF_SRC) -o $(ONEFA_BPF_OBJ)

$(ONEFA_SKEL): $(ONEFA_BPF_OBJ)
	@echo "Generating 1FASketch skeleton..."
	$(BPFTOOL) gen skeleton $(ONEFA_BPF_OBJ) > $(ONEFA_SKEL)

$(ONEFA_USER_BIN): $(ONEFA_USER_SRC) $(ONEFA_SKEL) $(ONEFA_COMMON)
	@echo "Compiling 1FASketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -D_BPF_H_ $(ONEFA_USER_SRC) -o $(ONEFA_USER_BIN) $(LIBBPF_LDFLAGS) -lpcap




elastic: elastic-build

elastic-build: $(ELASTIC_USER_BIN)
	@echo "=== ElasticSketch built successfully ==="

$(ELASTIC_BPF_OBJ): $(ELASTIC_BPF_SRC) $(ELASTIC_COMMON) $(VMLINUX)
	@echo "Compiling ElasticSketch BPF program..."
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(ELASTIC_BPF_SRC) -o $(ELASTIC_BPF_OBJ)
	$(LLVM_STRIP) -g $(ELASTIC_BPF_OBJ)

$(ELASTIC_SKEL): $(ELASTIC_BPF_OBJ)
	@echo "Generating ElasticSketch skeleton..."
	$(BPFTOOL) gen skeleton $(ELASTIC_BPF_OBJ) > $(ELASTIC_SKEL)

$(ELASTIC_USER_BIN): $(ELASTIC_USER_SRC) $(ELASTIC_SKEL) $(ELASTIC_COMMON)
	@echo "Compiling ElasticSketch loader..."
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -D_BPF_H_ $(ELASTIC_USER_SRC) -o $(ELASTIC_USER_BIN) $(LIBBPF_LDFLAGS) -lpcap


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

onefa-run: onefa-build
	@echo "=== Running 1FASketch ==="
	@echo "Interface: $(ONEFA_IFACE)"
	@echo "Top-K: $(ONEFA_TOPK)"
	@echo "Duration: $(ONEFA_DURATION)s"
	@echo "PCAP: $(ONEFA_PCAP)"
	@echo ""
	@echo ""
	sudo ./$(ONEFA_USER_BIN) -i $(ONEFA_IFACE) -k $(ONEFA_TOPK) -D $(ONEFA_DURATION) -t $(ONEFA_PCAP)

elastic-run: elastic-build
	@echo "=== Running ElasticSketch ==="
	@echo "Interface: $(ELASTIC_IFACE)"
	@echo "Top-K: $(ELASTIC_TOPK)"
	@echo "Duration: $(ELASTIC_DURATION)s"
	@echo "PCAP: $(ELASTIC_PCAP)"
	@echo ""
	sudo ./$(ELASTIC_USER_BIN) -i $(ELASTIC_IFACE) -k $(ELASTIC_TOPK) -D $(ELASTIC_DURATION) -t $(ELASTIC_PCAP)


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

replay-onefa:
	@echo "=== Replaying packets for 1FASketch ==="
	@echo "Interface: $(ONEFA_REPLAY_IFACE)"
	@echo "PCAP: $(ONEFA_PCAP)"
	sudo tcpreplay --intf1=$(ONEFA_REPLAY_IFACE) --topspeed $(ONEFA_PCAP)

replay-elastic:
	@echo "=== Replaying packets for ElasticSketch ==="
	@echo "Interface: $(ELASTIC_REPLAY_IFACE)"
	@echo "PCAP: $(ELASTIC_PCAP)"
	sudo tcpreplay --intf1=$(ELASTIC_REPLAY_IFACE) --topspeed $(ELASTIC_PCAP)


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
	@sudo tcpreplay --intf1=$(TWOFA_REPLAY_IFACE) --topspeed $(TWOFA_PCAP) || true
	@echo "Waiting for 2FASketch auto-detection..."
	@sleep $(TWOFA_DURATION)
	@echo ""
	@echo "=== 2FASketch Test Results ==="
	@cat twofa_test_output.log | tr -d '\r'
	@rm -f /tmp/twofa_loader.pid

test-onefa: onefa-build
	@echo "=== Running 1FASketch automated test ==="
	@echo "Starting 1FASketch in background..."
	sudo ./$(ONEFA_USER_BIN) -i $(ONEFA_IFACE) -k $(ONEFA_TOPK) -D $(ONEFA_DURATION) -t $(ONEFA_PCAP) > onefa_test_output.log 2>&1 & echo $$! > /tmp/onefa_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(ONEFA_REPLAY_IFACE) --topspeed $(ONEFA_PCAP) || true
	@echo "Waiting for 1FASketch auto-detection..."
	@sleep $(ONEFA_DURATION)
	@echo ""
	@echo "=== 1FASketch Test Results ==="
	@cat onefa_test_output.log | tr -d '\r'
	@rm -f /tmp/onefa_loader.pid

test-elastic: elastic-build
	@echo "=== Running ElasticSketch automated test ==="
	@echo "Starting ElasticSketch in background..."
	sudo ./$(ELASTIC_USER_BIN) -i $(ELASTIC_IFACE) -k $(ELASTIC_TOPK) -D $(ELASTIC_DURATION) -t $(ELASTIC_PCAP) > elastic_test_output.log 2>&1 & echo $$! > /tmp/elastic_loader.pid
	@sleep 2
	@echo "Replaying PCAP..."
	@sudo tcpreplay --intf1=$(ELASTIC_REPLAY_IFACE) --topspeed $(ELASTIC_PCAP) || true
	@echo "Waiting for ElasticSketch collection..."
	@sleep $(ELASTIC_DURATION)
	@sleep 2
	@echo ""
	@echo "=== ElasticSketch Test Results ==="
	@cat elastic_test_output.log | tr -d '\r'
	@rm -f /tmp/elastic_loader.pid




stop-xdp-stable:
	@echo "Detaching StableSketch XDP from $(IFACE)..."
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

stop-xdp-jigsaw:
	@echo "Detaching Jigsaw XDP from $(JIGSAW_IFACE)..."
	@sudo ip link set dev $(JIGSAW_IFACE) xdp off 2>/dev/null || true

stop-xdp-twofa:
	@echo "Detaching 2FASketch XDP from $(TWOFA_IFACE)..."
	@sudo ip link set dev $(TWOFA_IFACE) xdp off 2>/dev/null || true

stop-xdp-onefa:
	@echo "Detaching 1FASketch XDP from $(ONEFA_IFACE)..."
	@sudo ip link set dev $(ONEFA_IFACE) xdp off 2>/dev/null || true

stop-xdp-elastic:
	@echo "Detaching ElasticSketch XDP from $(ELASTIC_IFACE)..."
	@sudo ip link set dev $(ELASTIC_IFACE) xdp off 2>/dev/null || true




clean:
	@echo "Cleaning all build artifacts..."
	rm -f $(STABLE_BPF_OBJ) $(STABLE_SKEL) $(STABLE_USER_BIN)
	rm -f $(JIGSAW_BPF_OBJ) $(JIGSAW_USER_BIN)
	rm -f $(TWOFA_BPF_OBJ) $(TWOFA_SKEL) $(TWOFA_USER_BIN)
	rm -f $(ONEFA_BPF_OBJ) $(ONEFA_SKEL) $(ONEFA_USER_BIN)
	rm -f $(ELASTIC_BPF_OBJ) $(ELASTIC_SKEL) $(ELASTIC_USER_BIN)
	rm -f stable_test_output.log jigsaw_test_output.log twofa_test_output.log onefa_test_output.log elastic_test_output.log
	rm -f /tmp/stable_sketch.pid /tmp/jigsaw_loader.pid /tmp/twofa_loader.pid /tmp/onefa_loader.pid /tmp/elastic_loader.pid
	@echo "Cleaning Jigsaw pinned maps..."
	@sudo rm -f $(JIGSAW_PIN_DIR)/aux_map $(JIGSAW_PIN_DIR)/bucket_map $(JIGSAW_PIN_DIR)/xdp_stats_map 2>/dev/null || true
	@echo "Done"

clean-all: clean
	@echo "Removing vmlinux.h..."
	rm -f $(VMLINUX)