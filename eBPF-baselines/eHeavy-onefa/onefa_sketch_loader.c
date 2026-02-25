#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include "onefa_sketch_common.h"
#include "onefa_sketch_ebpf.skel.h"

#define BPF_MAJOR_VERSION
#undef BPF_MAJOR_VERSION

#define HASH_MAP_SIZE 1000000

typedef struct HashEntry {
    uint8_t key[KEY_LEN];
    uint32_t value;
    struct HashEntry* next;
} HashEntry;

typedef struct {
    HashEntry* buckets[HASH_MAP_SIZE];
    uint32_t size;
} HashMap;

static uint32_t hash_key(const uint8_t* key) {
    uint32_t hash = 5381;
    for (int i = 0; i < KEY_LEN; i++) {
        hash = ((hash << 5) + hash) + key[i];
    }
    return hash % HASH_MAP_SIZE;
}

HashMap* HashMap_create() {
    return calloc(1, sizeof(HashMap));
}

void HashMap_increment(HashMap* map, const uint8_t* key) {
    uint32_t index = hash_key(key);
    HashEntry* entry = map->buckets[index];
    
    while (entry) {
        if (memcmp(entry->key, key, KEY_LEN) == 0) {
            entry->value++;
            return;
        }
        entry = entry->next;
    }
    
    entry = malloc(sizeof(HashEntry));
    memcpy(entry->key, key, KEY_LEN);
    entry->value = 1;
    entry->next = map->buckets[index];
    map->buckets[index] = entry;
    map->size++;
}

void HashMap_destroy(HashMap* map) {
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        HashEntry* entry = map->buckets[i];
        while (entry) {
            HashEntry* temp = entry;
            entry = entry->next;
            free(temp);
        }
    }
    free(map);
}

int extract_5tuple(const uint8_t* packet, uint32_t len, uint8_t* key) {
    if (len < sizeof(struct ether_header) + sizeof(struct ip))
        return -1;
    
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return -1;
    
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    if (ip_hdr->ip_v != 4)
        return -1;
    
    uint32_t src_ip = ntohl(ip_hdr->ip_src.s_addr);
    uint32_t dst_ip = ntohl(ip_hdr->ip_dst.s_addr);

    key[0] = (src_ip >> 24) & 0xFF;
    key[1] = (src_ip >> 16) & 0xFF;
    key[2] = (src_ip >> 8) & 0xFF;
    key[3] = src_ip & 0xFF;
    key[4] = (dst_ip >> 24) & 0xFF;
    key[5] = (dst_ip >> 16) & 0xFF;
    key[6] = (dst_ip >> 8) & 0xFF;
    key[7] = dst_ip & 0xFF;
    
    uint16_t src_port = 0, dst_port = 0;
    uint8_t* transport = (uint8_t*)ip_hdr + (ip_hdr->ip_hl * 4);
    
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        if ((uint8_t*)ip_hdr + len < transport + sizeof(struct tcphdr))
            return -1;
        struct tcphdr* tcp = (struct tcphdr*)transport;
        src_port = ntohs(tcp->th_sport);
        dst_port = ntohs(tcp->th_dport);
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        if ((uint8_t*)ip_hdr + len < transport + sizeof(struct udphdr))
            return -1;
        struct udphdr* udp = (struct udphdr*)transport;
        src_port = ntohs(udp->uh_sport);
        dst_port = ntohs(udp->uh_dport);
    }
    
    key[8] = (src_port >> 8) & 0xFF;
    key[9] = src_port & 0xFF;
    key[10] = (dst_port >> 8) & 0xFF;
    key[11] = dst_port & 0xFF;
    key[12] = ip_hdr->ip_p;
    
    return 0;
}

typedef struct {
    uint32_t fp;
    uint32_t count;
} FlowResult;

int cmp_flows(const void* a, const void* b) {
    return ((FlowResult*)b)->count - ((FlowResult*)a)->count;
}

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s -i <interface> -t <pcap_file> [-k <topk>] [-D <duration>]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <interface>   Network interface to attach XDP (required)\n");
    fprintf(stderr, "  -t <pcap_file>   PCAP file for ground truth (required)\n");
    fprintf(stderr, "  -k <topk>        Top-K flows to report (default: 1000)\n");
    fprintf(stderr, "  -D <duration>    Duration in seconds (default: 10, use 0 for auto-detect)\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -k 500 -D 10\n", prog);
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -D 0  # Auto-detect mode\n", prog);
}

int main(int argc, char** argv) {
    const char* ifname = NULL;
    const char* pcap_file = NULL;
    int top_k = 1000;
    int duration = 10;  
    int opt;

    while ((opt = getopt(argc, argv, "i:t:k:D:h")) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 't':
                pcap_file = optarg;
                break;
            case 'k':
                top_k = atoi(optarg);
                break;
            case 'D':
                duration = atoi(optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (!ifname || !pcap_file) {
        fprintf(stderr, "Error: Missing required arguments\n\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("PCAP: %s\n", pcap_file);
    printf("Top-K: %d\n", top_k);
    printf("Memory: %d KB\n", SKETCH_MEMORY);
    printf("Buckets calculated: %d\n", MAX_BUCKETS);
    
    printf("[1/4] Building ground truth from PCAP...\n");
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(pcap_file, errbuf);
    if (!pcap) {
        fprintf(stderr, "Failed to open PCAP: %s\n", errbuf);
        return 1;
    }
    
    HashMap* ground_truth = HashMap_create();
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    uint32_t packet_count = 0;
    
    while (pcap_next_ex(pcap, &header, &packet) >= 0) {
        uint8_t key[KEY_LEN];
        if (extract_5tuple(packet, header->caplen, key) == 0) {
            HashMap_increment(ground_truth, key);
            packet_count++;
        }
    }
    pcap_close(pcap);
    printf("   Ground truth: %u packets, %u flows\n\n", packet_count, ground_truth->size);
    
    printf("[2/4] Loading eBPF program...\n");
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct onefa_sketch_ebpf* skel = onefa_sketch_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load eBPF\n");
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    int sketch_fd = bpf_map__fd(skel->maps.sketch_map);
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        onefa_sketch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    struct Elastic_1FASketch sk = {};
    sk.hp.bucket_num = MAX_BUCKETS;
    for (int i = 0; i < MAX_BUCKETS; i++) {
        for (int j = 0; j < COUNTER_PER_BUCKET; j++) {
            sk.hp.buckets[i].slots[j].fp = 0;
            sk.hp.buckets[i].slots[j].value = 0;
        }
    }
    
    uint32_t map_key = 0;
    if (bpf_map_update_elem(sketch_fd, &map_key, &sk, BPF_ANY) != 0) {
        perror("Failed to init sketch");
        onefa_sketch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    struct bpf_link* link = bpf_program__attach_xdp(skel->progs.xdp_collect_1fa, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP\n");
        onefa_sketch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    printf("   eBPF attached to %s\n\n", ifname);
    
    int counter_fd = bpf_map__fd(skel->maps.insert_counter);
    
    printf("[3/4] Monitoring traffic...\n");
    if (duration == 0) {
        printf("   Mode: Auto-detect (will stop when traffic ceases)\n");
    } else {
        printf("   Mode: Fixed duration (%d seconds)\n", duration);
    }
    
    uint64_t prev_total = 0;
    struct timespec start_time, end_time;
    int started = 0;
    int idle_count = 0;
    const int IDLE_THRESHOLD = 3; // 3 seconds of no new packets
    int elapsed_time = 0;
    
    while (1) {
        sleep(1);
        elapsed_time++;
        
        if (counter_fd >= 0) {
            uint64_t vals[64];
            int nr_cpus = libbpf_num_possible_cpus();
            if (bpf_map_lookup_elem(counter_fd, &map_key, &vals) == 0) {
                uint64_t total = 0;
                for (int i = 0; i < nr_cpus; i++) total += vals[i];
                
                if (total > 0 && !started) {
                    clock_gettime(CLOCK_MONOTONIC, &start_time);
                    started = 1;
                }
                
                if (total != prev_total) {
                    fflush(stdout);
                    prev_total = total;
                    idle_count = 0;
                } else if (started && total > 0) {
                    idle_count++;
                    
                    if (duration == 0 && idle_count >= IDLE_THRESHOLD) {
                        clock_gettime(CLOCK_MONOTONIC, &end_time);
                        break;
                    }
                }
                
                if (duration > 0 && started && elapsed_time >= duration) {
                    clock_gettime(CLOCK_MONOTONIC, &end_time);
                    break;
                }
            }
        }
        
        if (!started && elapsed_time >= 60) {
            bpf_link__destroy(link);
            onefa_sketch_ebpf__destroy(skel);
            HashMap_destroy(ground_truth);
            return 1;
        }
    }
    
    printf("\n");
    sleep(1);
    
    double elapsed = 0.0;
    if (started) {
        elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                  (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    }
    
    int debug_fd = bpf_map__fd(skel->maps.debug_map);
    if (debug_fd >= 0) {
        __u32 keys[3] = {0, 1, 2};
        __u32 vals[3] = {0, 0, 0};
        
        bpf_map_lookup_elem(debug_fd, &keys[0], &vals[0]);
        bpf_map_lookup_elem(debug_fd, &keys[1], &vals[1]);
        bpf_map_lookup_elem(debug_fd, &keys[2], &vals[2]);

    printf("[4/4] Analyzing results...\n");
    if (bpf_map_lookup_elem(sketch_fd, &map_key, &sk) != 0) {
        fprintf(stderr, "Failed to read sketch\n");
        bpf_link__destroy(link);
        onefa_sketch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    printf("   eBPF stats: cnt_all=%u\n", sk.hp.cnt_all);
    
    if (elapsed > 0) {
        double pps = prev_total / elapsed;
        double mpps = pps / 1e6;
        printf("   Processing time: %.3f seconds\n", elapsed);
        printf("   Throughput: %.2f Mpps (%.0f pps)\n\n", mpps, pps);
    }
    
    FlowResult* ebpf_flows = malloc(MAX_BUCKETS * MAX_VALID_COUNTER * sizeof(FlowResult));
    int ebpf_count = 0;
    
    for (int i = 0; i < MAX_BUCKETS; i++) {
        for (int j = 0; j < MAX_VALID_COUNTER; j++) {
            if (sk.hp.buckets[i].slots[j].fp != 0 && sk.hp.buckets[i].slots[j].value > 0) {
                ebpf_flows[ebpf_count].fp = sk.hp.buckets[i].slots[j].fp;
                ebpf_flows[ebpf_count].count = sk.hp.buckets[i].slots[j].value;
                ebpf_count++;
            }
        }
    }
    
    qsort(ebpf_flows, ebpf_count, sizeof(FlowResult), cmp_flows);
    printf("   eBPF detected: %d flows\n\n", ebpf_count);
    printf("Top 10 eBPF Fingerprints: \n");
    for(int i=0; i<10 && i<ebpf_count; i++){
        printf(" %u (0x%08X) -> %u packets\n", ebpf_flows[i].fp, ebpf_flows[i].fp, ebpf_flows[i].count);
    }
    
    // Build GT top-K
    FlowResult* gt_flows = malloc(ground_truth->size * sizeof(FlowResult));
    int gt_count = 0;
    
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        HashEntry* entry = ground_truth->buckets[i];
        while (entry) {
            uint32_t fp = (entry->key[3] << 24) | (entry->key[2] << 16) |
                         (entry->key[1] << 8) | entry->key[0];
            gt_flows[gt_count].fp = fp;
            gt_flows[gt_count].count = entry->value;
            gt_count++;
            entry = entry->next;
        }
    }
    
    qsort(gt_flows, gt_count, sizeof(FlowResult), cmp_flows);

    printf("\nTop 10 Ground truth fingerprints : \n");
    for (int i=0; i<10 && i<gt_count; i++){
        printf("%u -> %u packets\n", gt_flows[i].fp, gt_flows[i].count);
    }
    
    int threshold_idx = (top_k < gt_count) ? top_k - 1 : gt_count - 1;
    int threshold = gt_flows[threshold_idx].count;
    
    int TP = 0, FP = 0;
    double sum_are = 0, sum_aae = 0;
    
    for (int i = 0; i < ebpf_count && i < top_k; i++) {
        uint32_t fp = ebpf_flows[i].fp;
        uint32_t ebpf_cnt = ebpf_flows[i].count;
        
        for (int j = 0; j < gt_count; j++) {
            if (gt_flows[j].fp == fp) {
                uint32_t gt_cnt = gt_flows[j].count;
                if (gt_cnt >= threshold) {
                    TP++;
                    double error = abs((int)ebpf_cnt - (int)gt_cnt);
                    sum_aae += error;
                    sum_are += error / gt_cnt;
                } else {
                    FP++;
                }
                break;
            }
        }
    }
    
    int gt_heavy = 0;
    for (int i = 0; i < gt_count && gt_flows[i].count >= threshold; i++) {
        gt_heavy++;
    }
    
    int FN = gt_heavy - TP;
    double precision = (TP + FP > 0) ? (double)TP / (TP + FP) : 0;
    double recall = (gt_heavy > 0) ? (double)TP / gt_heavy : 0;
    double f1 = (precision + recall > 0) ? 2 * precision * recall / (precision + recall) : 0;
    double are = (TP > 0) ? sum_are / TP : 0;
    double aae = (TP > 0) ? sum_aae / TP : 0;
    
    printf("\n=== RESULTS ===\n");
    printf("Threshold (top-%d): %d packets\n", top_k, threshold);
    printf("GT Heavy Hitters: %d\n", gt_heavy);
    printf("eBPF Reported: %d\n\n", (ebpf_count < top_k ? ebpf_count : top_k));
    printf("TP=%d, FP=%d, FN=%d\n\n", TP, FP, FN);
    printf("Precision: %.6f\n", precision);
    printf("Recall: %.6f\n", recall);
    printf("F1-Score: %.6f\n", f1);
    printf("ARE: %.6f\n", are);
    printf("AAE: %.2f\n", aae);
    
    free(ebpf_flows);
    free(gt_flows);
    bpf_link__destroy(link);
    onefa_sketch_ebpf__destroy(skel);
    HashMap_destroy(ground_truth);
    return 0;
}