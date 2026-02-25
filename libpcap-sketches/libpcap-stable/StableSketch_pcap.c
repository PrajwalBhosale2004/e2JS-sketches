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

#include "StableSketch.c"

#include "util.h"

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

static StableSketch * sketch;


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
        StableSketch_Update(sketch, key, 1);
        processed_packets++;
        total_inserts++;
    }
}


static void signal_handler(int signum) {
    fprintf(stderr, "\n\nCaught signal %d, stopping capture...\n", signum);
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


static void display_results(int K) {
     
    printf("%-4s %-18s %-6s %-18s %-6s %-8s %-10s\n",
           "No", "Src IP", "S.Port", "Dst IP", "D.Port", "Proto", "Count");
    int i=0;
    for ( i = 0; i < 1000; i++) {
        char result_str[KEY_LEN + 1];
        int result_val;
        
        pkt_5tuple tuple;
        tuple.src_ip = ((uint32_t)(unsigned char)result_str[0] << 24) |
                      ((uint32_t)(unsigned char)result_str[1] << 16) |
                      ((uint32_t)(unsigned char)result_str[2] << 8) |
                      ((uint32_t)(unsigned char)result_str[3]);
        
        tuple.dst_ip = ((uint32_t)(unsigned char)result_str[4] << 24) |
                      ((uint32_t)(unsigned char)result_str[5] << 16) |
                      ((uint32_t)(unsigned char)result_str[6] << 8) |
                      ((uint32_t)(unsigned char)result_str[7]);
        
        tuple.src_port = ((uint16_t)(unsigned char)result_str[8] << 8) |
                        ((uint16_t)(unsigned char)result_str[9]);
        
        tuple.dst_port = ((uint16_t)(unsigned char)result_str[10] << 8) |
                        ((uint16_t)(unsigned char)result_str[11]);
        
        tuple.proto = (unsigned char)result_str[12];
        
        struct in_addr src_addr = {.s_addr = htonl(tuple.src_ip)};
        struct in_addr dst_addr = {.s_addr = htonl(tuple.dst_ip)};
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);
        
        const char *proto_str = (tuple.proto == IPPROTO_TCP) ? "TCP" :
                               (tuple.proto == IPPROTO_UDP) ? "UDP" : "OTHER";
        
        printf("%-4d %-18s %-6u %-18s %-6u %-8s %-10d\n",
               i + 1, src_ip_str, tuple.src_port, 
               dst_ip_str, tuple.dst_port, proto_str, result_val);
    }
    printf("value of I: %d\n" , i);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [-k top_k] [-m memory_kb] [-t duration_sec]\n", argv[0]);
        fprintf(stderr, "Example: %s veth-recv -k 1000 -m 300 -t 10\n", argv[0]);
        return 1;
    }
    
    char *interface = argv[1];
    int K = 1000;
    int MEM = 1000;  
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
    
    sketch = StableSketch_create(4, 1024, 13);
        
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
        return 1;
    }
    global_handle = handle;
    
    
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter\n");
        pcap_close(handle);
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);
    
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
            keep_running = 0;
            break;
        }
    }
    
    
    if (current_second_packets > 0) {
        print_per_second_stats(current_second, current_second_packets);
    }
        
    
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
    
    
    display_results(K);
    global_handle = NULL;
    
    
    pcap_close(handle);
    StableSketch_destroy(sketch);
    return 0;
}
