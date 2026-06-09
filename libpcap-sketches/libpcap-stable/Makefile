# Makefile for BubbleSketch and StableSketch implementations

CC = gcc
CFLAGS = -Wall -O3 -std=gnu99 -pthread
LDFLAGS = -lm -lpcap

STABLE_MAIN_SRC = StableSketch_main.c StableSketch.c hash.c
STABLE_PCAP_SRC = StableSketch_pcap.c StableSketch.c hash.c

STABLE_MAIN = stable_main
STABLE_PCAP = stable_pcap

# Targets
all: $(STABLE_MAIN) $(STABLE_PCAP)

$(STABLE_MAIN): $(STABLE_MAIN_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(STABLE_PCAP): $(STABLE_PCAP_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Individual targets

stable_only: $(STABLE_MAIN) $(STABLE_PCAP)

# Clean
clean:
	rm -f $(STABLE_MAIN) $(STABLE_PCAP) *.o

# Usage examples
help:
	@echo "Usage:"
	@echo "  make                    - Build all executables"
	@echo "  make bubble_only        - Build only BubbleSketch programs"
	@echo "  make stable_only        - Build only StableSketch programs"
	@echo "  make clean              - Remove all built files"
	@echo ""
	@echo "Running examples:"
	@echo "  BubbleSketch with dataset:"
	@echo "    ./$(BUBBLE_MAIN) -d 10.dat -m 300 -k 1000"
	@echo ""
	@echo "  BubbleSketch with pcap:"
	@echo "    sudo ./$(BUBBLE_PCAP) eth0 -m 300 -k 1000 -t 10"
	@echo ""
	@echo "  StableSketch with dataset:"
	@echo "    ./$(STABLE_MAIN) -d 10.dat -m 300 -k 1000"
	@echo ""
	@echo "  StableSketch with pcap:"
	@echo "    sudo ./$(STABLE_PCAP) eth0 -m 300 -k 1000 -t 10"

.PHONY: all bubble_only stable_only clean help