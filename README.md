# **e2JS : A collection of eBPF-based sketches for Heavy Hitter and Persistent flow detection**

## **e2JS-sketches :**

### **1) eHeavy-sketches : eBPF-based sketches for Heavy hitter detection.**

Consists of eHeavy-twofa, eHeavy-jigsaw and eHeavy-stable.

### **2) ePersistent-sketches : eBPF-based sketches for Persistent flow detection.**

Consists of ePersistent-twofa, ePersistent-jigsaw and ePersistent-stable.

### **3) eMultiHeavy-sketches : eBPF-based sketches for multi-dimensional heavy hitter detection.**

Consists of eMultiHeavy-twofa, eMultiHeavy-jigsaw and eMultiHeavy-stable.

### **4) eRegularized-stable : Enhanced version of eHeavy-stable that deals with the irregularities caused by the probabilistic decay replacement policy of eHeavy-stable.**

### **5) eRecent-twofa : Specialized version of eHeavy-twofa which achieves a high reduction in errors under bursty traffic conditions.**

---

## **Prerequisites**

Linux kernel with eBPF support

Clang compiler

libbpf development libraries

libpcap (for user-space variant)

tcpreplay (for testing)

---

## **Initial Setup**

Before running any sketch algorithms, set up the virtual Ethernet pair for eBPF testing:

```bash
chmod +x setup_veth.sh
./setup_veth.sh
```

Generate the vmlinux.h file (one-time process):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

---

## **Repository Structure**

The repository contains the following folders:

1. eHeavy-sketches: Code files for eHeavy-sketches.
2. ePersistent-sketches: Code files for ePersistent-sketches.
3. eMultiHeavy-sketches: Code files for eMultiHeavy-sketches.
4. eRecent-twofa: Code files for eRecent-twofa.
5. eRegularized-stable: Code files for eRegularized-stable.
6. libpcap-sketches: Code files for libpcap-sketches which are user space C versions of Stable-Sketch, 2FA Sketch and Jigsaw-Sketch which read packets through the network interface.
7. eBPF-baselines

Code files for the eBPF-based versions of baseline algorithms.

| Sketch           | Baseline Algorithms |
|------------------|--------------------|
| eHeavy-twofa     | eHeavy-onefa, eHeavy-elastic |
| eHeavy-jigsaw    | eHeavy-heavyguardian, eHeavy-chainsketch, eHeavy-wavingsketch, eHeavy-uasketch |
| eHeavy-stable    | eHeavy-mv, eHeavy-elastic |

8. dats : Folder containing all the .dat files needed for the experimentation.

---

## **Building and Running (eHeavy-sketches, ePersistent-sketches, eMultiHeavy-sketches, eRegularized-stable, eRecent-twofa)**

Go to particular sketch folder and use the following commands (Replace <Sketch> with respective sketch name)

Clean build artifacts:

```bash
make clean
```

Build sketch:

```bash
make <Sketch>
```

Run sketch (On Terminal 1):

```bash
sudo make <Sketch>-run IFACE=<interface>
```

Replay traffic (On Terminal 2):

```bash
sudo make replay-<Sketch>
```

Automated full experiment:

```bash
sudo make test-<Sketch>
```

---

## **Building and Running (libpcap-sketches)**

The libpcap-sketches folder contains implementations that run in user-space:

Compilation:

1. Go to specific libpcap-sketch folder

2.

```bash
gcc <Sketch>_pcap.c -o <Sketch>_pcap -lpcap
```

Execution:

3.

```bash
./<Sketch>_pcap <interface> [-k top_k] [-m memory_kb] [-t duration_sec]
```

Parameters:

<interface>: Network interface to monitor (e.g., eth0, veth-send)
-k top_k: Number of top heavy hitters to track (optional)
-m memory_kb: Memory size in KB (optional)
-t duration_sec: Duration to capture traffic in seconds (optional)

---

## **Workflow Summary**

1. Generate vmlinux.h (one-time)
2. Setup veth pair (once every system startup)
3. (a) For automated test,

```bash
make clean && make test-<Sketch>
```

(b) Else,

```bash
make clean && make <Sketch> && make <Sketch>-run
```

(Terminal 1)

```bash
make replay-<Sketch>
```

(Terminal 2)

4. View results

---

## **Notes**

Ensure all commands are run with appropriate permissions (some may require sudo)
The veth pair setup is required only once unless the network configuration changes
PCAP files should be prepared from .dat files in the dats/ directory
Each variant implements different optimization strategies for heavy hitter detection

---

## **Troubleshooting**

If compilation fails, ensure all dependencies (libbpf, clang, kernel headers) are installed
For permission errors, run with sudo where necessary
Verify the veth interfaces exist with ip link show before running tests
