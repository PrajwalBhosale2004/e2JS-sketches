#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include "twofa_sketch.c"

#define KEY_LEN 13
#define SNAPLEN 128  
#define PROMISC 1
#define TIMEOUT_MS 1

static volatile uint64_t total_packets = 0;
static volatile uint64_t processed_packets = 0;
static volatile uint64_t total_inserts = 0;
static volatile int keep_running = 1;
static pcap_t *global_handle = NULL;

static volatile uint64_t last_second_packets = 0;
static volatile uint64_t current_second_packets = 0;
static volatile int current_second = 0;

static Elastic_2FASketch* sketch = NULL;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
} __attribute__((packed)) pkt_5tuple;

static void tuple_to_key(pkt_5tuple *tuple, char *key) {
    memset(key, 0, 14);
    
    key[0] = (tuple->src_ip >> 24) & 0xFF;
    key[1] = (tuple->src_ip >> 16) & 0xFF;
    key[2] = (tuple->src_ip >> 8) & 0xFF;
    key[3] = tuple->src_ip & 0xFF;
    
    key[4] = (tuple->dst_ip >> 24) & 0xFF;
    key[5] = (tuple->dst_ip >> 16) & 0xFF;
    key[6] = (tuple->dst_ip >> 8) & 0xFF;
    key[7] = tuple->dst_ip & 0xFF;
    
    key[8] = (tuple->src_port >> 8) & 0xFF;
    key[9] = tuple->src_port & 0xFF;
    
    key[10] = (tuple->dst_port >> 8) & 0xFF;
    key[11] = tuple->dst_port & 0xFF;
    
    key[12] = tuple->proto;
}

static int parse_packet(const uint8_t *packet, uint32_t len, pkt_5tuple *tuple) {
    if (len < sizeof(struct ether_header)) {
        return -1;
    }
    
    struct ether_header *eth = (struct ether_header *)packet;
    
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return -1;
    }
    
    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    
    if (len < sizeof(struct ether_header) + sizeof(struct ip)) {
        return -1;
    }
    
    tuple->src_ip = ntohl(iph->ip_src.s_addr);
    tuple->dst_ip = ntohl(iph->ip_dst.s_addr);
    tuple->proto = iph->ip_p;
    
    uint32_t ip_hdr_len = iph->ip_hl * 4;
    uint32_t transport_offset = sizeof(struct ether_header) + ip_hdr_len;
    
    if (iph->ip_p == IPPROTO_TCP) {
        if (len < transport_offset + sizeof(struct tcphdr)) {
            return -1;
        }
        struct tcphdr *tcph = (struct tcphdr *)(packet + transport_offset);
        tuple->src_port = ntohs(tcph->th_sport);
        tuple->dst_port = ntohs(tcph->th_dport);
    } else if (iph->ip_p == IPPROTO_UDP) {
        if (len < transport_offset + sizeof(struct udphdr)) {
            return -1;
        }
        struct udphdr *udph = (struct udphdr *)(packet + transport_offset);
        tuple->src_port = ntohs(udph->uh_sport);
        tuple->dst_port = ntohs(udph->uh_dport);
    } else {
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    
    return 0;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                          const u_char *packet) {
    if (!keep_running) {
        return;
    }

    total_packets++;
    current_second_packets++;

    pkt_5tuple tuple;
    if (parse_packet(packet, pkthdr->caplen, &tuple) == 0) {
        char key[14];
        tuple_to_key(&tuple, key);
        sketch_insert(sketch, (const uint8_t*)key, 1);
        processed_packets++;
        total_inserts++;
    }
}

static void signal_handler(int signum) {
    fprintf(stderr, "\n\n Caught signal %d, stopping capture...\n", signum);
    keep_running = 0;
    
    if (global_handle != NULL) {
        pcap_breakloop(global_handle);
    }
}

static void print_per_second_stats(int second, uint64_t packets_this_second) {
    double mpps = packets_this_second / 1000000.0;
    printf("Second %3d: %10lu packets  (%.6f Mpps)\n", 
           second, packets_this_second, mpps);
    fflush(stdout);
}

typedef struct {
    uint32_t fp;
    uint32_t count;
} ResultPair;

int result_compare(const void* a, const void* b) {
    const ResultPair* ra = (const ResultPair*)a;
    const ResultPair* rb = (const ResultPair*)b;
    return rb->count - ra->count;  
}

static void display_results(int K) {
    printf("\n\n========== 2FASketch Results ==========\n");
    printf("Total packets captured: %lu\n", total_packets);
    printf("Processed packets: %lu\n", processed_packets);
    printf("Total inserts: %lu\n", total_inserts);
    printf("Heavy part evictions: %u\n\n", sketch->hp.cnt_all);
    
    uint32_t* out_keys = (uint32_t*)malloc(K * sizeof(uint32_t));
    uint32_t* out_vals = (uint32_t*)malloc(K * sizeof(uint32_t));
    int out_num = K;
    
    sketch_get_heavy_hitters(sketch, 1, out_keys, out_vals, &out_num);
    
    ResultPair* results = (ResultPair*)malloc(out_num * sizeof(ResultPair));
    for (int i = 0; i < out_num; i++) {
        results[i].fp = out_keys[i];
        results[i].count = out_vals[i];
    }
    qsort(results, out_num, sizeof(ResultPair), result_compare);
    
    printf("%-4s %-12s %-10s\n",
           "No", "Fingerprint", "Count");
    

    int display_count = (out_num < K) ? out_num : K;
    for (int i = 0; i < display_count; i++) {
        if (results[i].count == 0) break;
        
        printf("%-4d 0x%08x   %-10u\n",
               i + 1, 
               results[i].fp,
               results[i].count);
    }
    
    printf("\nNote: 2FASketch stores fingerprints (fp) instead of full keys.\n");
    printf("Full 5-tuple reconstruction is not possible from fingerprints alone.\n");
    printf("Displayed %d flows with frequency >= 1\n", display_count);
    
    free(out_keys);
    free(out_vals);
    free(results);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [-k top_k] [-m memory_kb] [-t duration_sec]\n", argv[0]);
        fprintf(stderr, "Example: %s veth-recv -k 1000 -m 300 -t 10\n", argv[0]);
        return 1;
    }
    
    char *interface = argv[1];
    int K = 1000;
    int MEM = 500;  
    int duration = 0;  
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            K = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            MEM = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            duration = atoi(argv[++i]);
        }
    }
    
    printf("=== 2FASketch Userspace Packet Capture ===\n");
    printf("Interface: %s\n", interface);
    printf("Memory: %d KB\n", MEM);
    printf("Top-K: %d\n", K);
    printf("Duration: %s\n", duration > 0 ? "limited" : "until Ctrl+C");
    printf("===========================================\n\n");
    
    int threshold = 100; 
    uint32_t bucket_num = (MEM * 1024) / (COUNTER_PER_BUCKET * sizeof(Counter));
    if (bucket_num > MAX_BUCKETS) bucket_num = MAX_BUCKETS;
    if (bucket_num == 0) bucket_num = 1;
    
    sketch = sketch_create(bucket_num, threshold);
    if (!sketch) {
        fprintf(stderr, "Failed to create 2FASketch!\n");
        return 1;
    }
    printf("2FASketch initialized with %u buckets in heavy part\n\n", 
           sketch->hp.bucket_num);
    
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, SNAPLEN, PROMISC, TIMEOUT_MS, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        fprintf(stderr, "Try running with sudo?\n");
        sketch_destroy(sketch);
        return 1;
    }
    global_handle = handle;
    
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter\n");
        pcap_close(handle);
        sketch_destroy(sketch);
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        pcap_freecode(&fp);
        pcap_close(handle);
        sketch_destroy(sketch);
        return 1;
    }
    pcap_freecode(&fp);
    
    printf("Capturing packets on %s... Press Ctrl+C to stop\n", interface);
    printf("===========================================\n\n");
    printf("Per-Second Throughput:\n");
    printf("%-10s %-15s %-15s\n", "Second", "Packets", "Rate");
    printf("-------------------------------------------\n");
    
    struct timeval start_time, last_second_time;
    gettimeofday(&start_time, NULL);
    last_second_time = start_time;
    current_second = 0;
    
    while (keep_running) {
        int ret = pcap_dispatch(handle, 1000, packet_handler, NULL);
        
        if (ret < 0) {
            fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(handle));
            break;
        }
        
        struct timeval current;
        gettimeofday(&current, NULL);
        
        if (current.tv_sec > last_second_time.tv_sec) {
            print_per_second_stats(current_second, current_second_packets);
            
            current_second++;
            last_second_packets = current_second_packets;
            current_second_packets = 0;
            last_second_time = current;
        }
        
        if (duration > 0 && (current.tv_sec - start_time.tv_sec) >= duration) {
            printf("\n Duration limit reached\n");
            keep_running = 0;
            break;
        }
    }
    
    if (current_second_packets > 0) {
        print_per_second_stats(current_second, current_second_packets);
    }
    
    printf("\n\n Cleaning up...\n");
    
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    double total_time = (end_time.tv_sec - start_time.tv_sec) + 
                       (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    
    printf("\n\n========== Performance Statistics ==========\n");
    printf("Total runtime: %.2f seconds\n", total_time);
    printf("Total packets: %lu\n", total_packets);
    printf("Processed packets: %lu\n", processed_packets);
    if (total_time > 0) {
        printf("Average throughput: %.2f pkt/s\n", processed_packets / total_time);
        printf("Average throughput: %.6f Mpps\n", (processed_packets / total_time) / 1000000.0);
    }
    
    global_handle = NULL;
    
    pcap_close(handle);
    sketch_destroy(sketch);
    printf("\n Program terminated gracefully\n");
    return 0;
}
