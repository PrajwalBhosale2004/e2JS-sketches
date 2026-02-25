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
#include <pthread.h>
#include <time.h>
#include "twofa_epoch_common.h"
#include "twofa_epoch_ebpf.skel.h"

#define BPF_MAJOR_VERSION
#undef BPF_MAJOR_VERSION
#define HASH_MAP_SIZE 1000000
static volatile int keep_running = 1;
static int epoch_fd = -1;

static uint32_t key_to_fp_user(const uint8_t* key) {
    uint32_t hash = 0x9e3779b1;  
    
    for (int i = 0; i < KEY_LEN; i++) {
        hash ^= key[i];
        hash *= 0x85ebca77;  
        hash ^= (hash >> 13);
    }
    
    hash ^= (hash >> 16);
    hash *= 0x3243f6a9;
    hash ^= (hash >> 16);
    
    return hash;
}

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
    uint32_t last_update_epoch;  
} FlowResult;

int cmp_flows(const void* a, const void* b) {
    return ((FlowResult*)b)->count - ((FlowResult*)a)->count;
}

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s -i <interface> -t <pcap_file> [-k <topk>] [-D <duration>] [-s <scale>]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <interface>   Network interface to attach XDP (required)\n");
    fprintf(stderr, "  -t <pcap_file>   PCAP file for ground truth (required)\n");
    fprintf(stderr, "  -k <topk>        Top-K flows to report (default: 1000)\n");
    fprintf(stderr, "  -D <duration>    Duration in seconds (default: 10, use 0 for auto-detect)\n");
    fprintf(stderr, "  -s <scale>       Scale factor for GT counts (default: auto-calculate)\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -k 500 -D 10\n", prog);
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -D 0  # Auto-detect mode\n", prog);
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -s 4.0  # Use fixed scale factor\n", prog);
}

static void* epoch_update_thread(void* arg) {
    uint32_t epoch_key = 0;
    uint32_t current_epoch = 0;
    
    while (keep_running) {
        sleep(1);  
        current_epoch++;
        
        if (bpf_map_update_elem(epoch_fd, &epoch_key, &current_epoch, BPF_ANY) != 0) {
            fprintf(stderr, "Warning: Failed to update epoch counter\n");
        }
    }
    
    return NULL;
}

int main(int argc, char** argv) {
    const char* ifname = NULL;
    const char* pcap_file = NULL;
    int top_k = 1000;
    int duration = 10;
    double scale_factor = 0.0;  
    int opt;

    while ((opt = getopt(argc, argv, "i:t:k:D:s:h")) != -1) {
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
            case 's':
                scale_factor = atof(optarg);
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

    printf("=== 2FA Sketch ===\n");
    printf("PCAP: %s\n", pcap_file);
    printf("Top-K: %d\n", top_k);
    
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
    struct twofa_epoch_ebpf* skel = twofa_epoch_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load eBPF\n");
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    int sketch_fd = bpf_map__fd(skel->maps.sketch_map);
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        twofa_epoch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    epoch_fd = bpf_map__fd(skel->maps.epoch_counter);
    if (epoch_fd < 0) { 
        fprintf(stderr, "Failed to get epoch_counter map fd\n");
        twofa_epoch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }

    uint32_t epoch_key = 0;
    uint32_t initial_epoch = 0;
    if (bpf_map_update_elem(epoch_fd, &epoch_key, &initial_epoch, BPF_ANY) != 0) {
        perror("Failed to initialize epoch counter");
        twofa_epoch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }

    pthread_t epoch_thread;
    if (pthread_create(&epoch_thread, NULL, epoch_update_thread, NULL) != 0) {
        perror("Failed to create epoch thread");
        twofa_epoch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    printf("   Epoch updater started\n");

    struct Elastic_2FASketch sk = {};
    sk.hp.bucket_num = MAX_BUCKETS;
    sk.thres_set = 10;
    
    for (int i = 0; i < MAX_BUCKETS; i++) {
        for (int j = 0; j < COUNTER_PER_BUCKET; j++) {
            sk.hp.buckets[i].slots[j].fp = 0;
            sk.hp.buckets[i].slots[j].value = 0;
            sk.hp.buckets[i].slots[j].last_update_epoch = 0;
        }
    }
    
    uint32_t map_key = 0;
    if (bpf_map_update_elem(sketch_fd, &map_key, &sk, BPF_ANY) != 0) {
        perror("Failed to init sketch");
        twofa_epoch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    struct bpf_link* link = bpf_program__attach_xdp(skel->progs.xdp_collect_2fa, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP\n");
        twofa_epoch_ebpf__destroy(skel);
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
    const int IDLE_THRESHOLD = 3; 
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
            keep_running = 0;
            pthread_join(epoch_thread, NULL);
            bpf_link__destroy(link);
            twofa_epoch_ebpf__destroy(skel);
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
    
    printf("[4/4] Analyzing results...\n");
    if (bpf_map_lookup_elem(sketch_fd, &map_key, &sk) != 0) {
        fprintf(stderr, "Failed to read sketch\n");
        bpf_link__destroy(link);
        twofa_epoch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    printf("   eBPF stats: cnt=%u, cnt_all=%u\n", sk.hp.cnt, sk.hp.cnt_all);
    
    if (elapsed > 0) {
        double pps = prev_total / elapsed;
        double mpps = pps / 1e6;
        printf("   Processing time: %.3f seconds\n", elapsed);
        printf("   Throughput: %.2f Mpps (%.0f pps)\n\n", mpps, pps);
    }
    
    uint32_t current_epoch = 0;
    if (bpf_map_lookup_elem(epoch_fd, &epoch_key, &current_epoch) != 0) {
        fprintf(stderr, "Warning: Failed to read current epoch\n");
    }
    
    FlowResult* ebpf_flows = malloc(MAX_BUCKETS * MAX_VALID_COUNTER * sizeof(FlowResult));
    int ebpf_count = 0;
    
    for (int i = 0; i < MAX_BUCKETS; i++) {
        for (int j = 0; j < MAX_VALID_COUNTER; j++) {
            if (sk.hp.buckets[i].slots[j].fp != 0 && sk.hp.buckets[i].slots[j].value > 0) {
                ebpf_flows[ebpf_count].fp = sk.hp.buckets[i].slots[j].fp;
                ebpf_flows[ebpf_count].count = sk.hp.buckets[i].slots[j].value;
                ebpf_flows[ebpf_count].last_update_epoch = sk.hp.buckets[i].slots[j].last_update_epoch;
                ebpf_count++;
            }
        }
    }
    
    qsort(ebpf_flows, ebpf_count, sizeof(FlowResult), cmp_flows);
    printf("   eBPF detected: %d flows (using heavy part only)\n", ebpf_count);
    printf("   Current epoch: %u\n\n", current_epoch);
    
    FlowResult* gt_flows = malloc(ground_truth->size * sizeof(FlowResult));
    int gt_count = 0;
    
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        HashEntry* entry = ground_truth->buckets[i];
        while (entry) {
            uint32_t fp = key_to_fp_user(entry->key);
            
            gt_flows[gt_count].fp = fp;
            gt_flows[gt_count].count = entry->value;
            gt_flows[gt_count].last_update_epoch = 0;  
            gt_count++;
            entry = entry->next;
        }
    }
    
    qsort(gt_flows, gt_count, sizeof(FlowResult), cmp_flows);
    
    typedef struct {
        uint32_t fp;
        uint32_t count;
    } GTMapEntry;
    
    GTMapEntry* gt_map = malloc(gt_count * sizeof(GTMapEntry));
    for (int i = 0; i < gt_count; i++) {
        gt_map[i].fp = gt_flows[i].fp;
        gt_map[i].count = gt_flows[i].count;
    }
    
    
    printf("\n");
    free(gt_map);
    
    uint64_t total_ebpf_packets = 0;
    uint64_t total_gt_packets = 0;
    
    for (int i = 0; i < ebpf_count; i++) {
        total_ebpf_packets += ebpf_flows[i].count;
    }
    
    for (int i = 0; i < gt_count; i++) {
        total_gt_packets += gt_flows[i].count;
    }
    
    if (scale_factor <= 0.0) {
        if (total_gt_packets > 0) {
            scale_factor = (double)total_ebpf_packets / (double)total_gt_packets;
        } else {
            scale_factor = 1.0;
        }
    }
    
    int threshold_idx = (top_k < gt_count) ? top_k - 1 : gt_count - 1;
    int threshold = (int)(gt_flows[threshold_idx].count * scale_factor);
    
    int TP = 0, FP = 0;
    double sum_are = 0, sum_aae = 0;
    
    for (int i = 0; i < ebpf_count && i < top_k; i++) {
        uint32_t fp = ebpf_flows[i].fp;
        uint32_t ebpf_cnt = ebpf_flows[i].count;
        
        for (int j = 0; j < gt_count; j++) {
            if (gt_flows[j].fp == fp) {
                uint32_t gt_cnt = gt_flows[j].count;
                uint32_t gt_scaled = (uint32_t)(gt_cnt * scale_factor);
                if (gt_scaled >= threshold) {
                    TP++;
                    double error = abs((int)ebpf_cnt - (int)gt_scaled);
                    sum_aae += error;
                    sum_are += error / gt_scaled;
                } else {
                    FP++;
                }
                break;
            }
        }
    }
    
    int gt_heavy = 0;
    for (int i = 0; i < gt_count; i++) {
        uint32_t gt_scaled = (uint32_t)(gt_flows[i].count * scale_factor);
        if (gt_scaled >= threshold) {
            gt_heavy++;
        }
    }
    
    int FN = gt_heavy - TP;
    double precision = (TP + FP > 0) ? (double)TP / (TP + FP) : 0;
    double recall = (gt_heavy > 0) ? (double)TP / gt_heavy : 0;
    double f1 = (precision + recall > 0) ? 2 * precision * recall / (precision + recall) : 0;
    double are = (TP > 0) ? sum_are / TP : 0;
    double aae = (TP > 0) ? sum_aae / TP : 0;
    
    printf("\n=== RESULTS ===\n");
    printf("--- Traffic Scaling ---\n");
    printf("Total eBPF packets: %lu\n", total_ebpf_packets);
    printf("Total GT packets (from PCAP): %lu\n", total_gt_packets);
    printf("Scale factor (replays): %.2f\n", scale_factor);
    printf("(GT counts scaled by %.2f for comparison)\n\n", scale_factor);
    
    printf("Threshold (top-%d, scaled): %d packets\n", top_k, threshold);
    printf("GT Heavy Hitters (scaled): %d\n", gt_heavy);
    printf("eBPF Reported: %d\n\n", (ebpf_count < top_k ? ebpf_count : top_k));
    printf("TP=%d, FP=%d, FN=%d\n\n", TP, FP, FN);
    printf("Precision: %.6f\n", precision);
    printf("Recall: %.6f\n", recall);
    printf("F1-Score: %.6f\n", f1);
    printf("ARE: %.6f\n", are);
    printf("AAE: %.2f\n", aae);
    
    printf("=== DETAILED METRICS ===\n\n");
    
    printf("--- Top-10 Ground Truth Flows ---\n");
    printf("%-5s %-15s %-12s %-12s %-15s %-15s\n", "Rank", "Fingerprint", "GT Count", "GT Scaled", "eBPF Count", "Difference");
    printf("%-5s %-15s %-12s %-12s %-15s %-15s\n", "----", "-----------", "---------", "----------", "-----------", "----------");
    for (int i = 0; i < 10 && i < gt_count; i++) {
        uint32_t fp = gt_flows[i].fp;
        uint32_t gt_cnt = gt_flows[i].count;
        uint32_t gt_scaled = (uint32_t)(gt_cnt * scale_factor);
        
        uint32_t ebpf_cnt = 0;
        for (int j = 0; j < ebpf_count; j++) {
            if (ebpf_flows[j].fp == fp) {
                ebpf_cnt = ebpf_flows[j].count;
                break;
            }
        }
        
        printf("%-5d %-15u %-12u %-12u %-15u", i + 1, fp, gt_cnt, gt_scaled, ebpf_cnt);
        if (ebpf_cnt == 0) {
            printf(" (MISSED)");
        } else {
            int diff = (int)ebpf_cnt - (int)gt_scaled;
            if (diff != 0) {
                printf(" (%+d)", diff);
            } else {
                printf(" (match)");
            }
        }
        printf("\n");
    }
    
    printf("\n--- Top-10 eBPF Detected Flows ---\n");
    printf("%-5s %-15s %-12s %-12s %-12s %-12s %-15s\n", "Rank", "Fingerprint", "eBPF Count", "GT Count", "GT Scaled", "Age (epochs)", "Last Update");
    printf("%-5s %-15s %-12s %-12s %-12s %-12s %-15s\n", "----", "-----------", "---------", "---------", "----------", "------------", "-----------");
    for (int i = 0; i < 10 && i < ebpf_count; i++) {
        uint32_t fp = ebpf_flows[i].fp;
        uint32_t ebpf_cnt = ebpf_flows[i].count;
        uint32_t last_epoch = ebpf_flows[i].last_update_epoch;
        uint32_t age = (current_epoch >= last_epoch) ? (current_epoch - last_epoch) : 0;
        
        uint32_t gt_cnt = 0;
        for (int j = 0; j < gt_count; j++) {
            if (gt_flows[j].fp == fp) {
                gt_cnt = gt_flows[j].count;
                break;
            }
        }
        uint32_t gt_scaled = (uint32_t)(gt_cnt * scale_factor);
        
        printf("%-5d %-15u %-12u %-12u %-12u %-12u %-15u", i + 1, fp, ebpf_cnt, gt_cnt, gt_scaled, age, last_epoch);
        if (gt_cnt == 0) {
            printf(" (FP)");
        } else {
            int diff = (int)ebpf_cnt - (int)gt_scaled;
            if (diff != 0) {
                printf(" (%+d)", diff);
            } else {
                printf(" (match)");
            }
        }
        printf("\n");
    }
    
    printf("\n--- Recent Flows (updated in last 10 epochs, top-20 by count) ---\n");
    printf("%-5s %-15s %-12s %-12s %-12s %-12s %-15s\n", "Rank", "Fingerprint", "eBPF Count", "GT Count", "GT Scaled", "Age (epochs)", "Last Update");
    printf("%-5s %-15s %-12s %-12s %-12s %-12s %-15s\n", "----", "-----------", "---------", "---------", "----------", "------------", "-----------");
    
    FlowResult* recent_flows = malloc(ebpf_count * sizeof(FlowResult));
    int recent_count = 0;
    const uint32_t RECENT_THRESHOLD = 10;  
    
    for (int i = 0; i < ebpf_count; i++) {
        uint32_t age = (current_epoch >= ebpf_flows[i].last_update_epoch) ? 
                       (current_epoch - ebpf_flows[i].last_update_epoch) : 0;
        if (age <= RECENT_THRESHOLD) {
            recent_flows[recent_count] = ebpf_flows[i];
            recent_count++;
        }
    }
    
    qsort(recent_flows, recent_count, sizeof(FlowResult), cmp_flows);
    
    int print_count = (recent_count < 20) ? recent_count : 20;
    for (int i = 0; i < print_count; i++) {
        uint32_t fp = recent_flows[i].fp;
        uint32_t ebpf_cnt = recent_flows[i].count;
        uint32_t last_epoch = recent_flows[i].last_update_epoch;
        uint32_t age = (current_epoch >= last_epoch) ? (current_epoch - last_epoch) : 0;
        
        uint32_t gt_cnt = 0;
        for (int j = 0; j < gt_count; j++) {
            if (gt_flows[j].fp == fp) {
                gt_cnt = gt_flows[j].count;
                break;
            }
        }
        uint32_t gt_scaled = (uint32_t)(gt_cnt * scale_factor);
        
        printf("%-5d %-15u %-12u %-12u %-12u %-12u %-15u", i + 1, fp, ebpf_cnt, gt_cnt, gt_scaled, age, last_epoch);
        if (gt_cnt == 0) {
            printf(" (FP)");
        } else {
            int diff = (int)ebpf_cnt - (int)gt_scaled;
            if (diff != 0) {
                printf(" (%+d)", diff);
            } else {
                printf(" (match)");
            }
        }
        printf("\n");
    }
    
    if (recent_count == 0) {
        printf("(No flows updated in last %u epochs)\n", RECENT_THRESHOLD);
    } else {
        printf("\nTotal recent flows (age <= %u epochs): %d\n", RECENT_THRESHOLD, recent_count);
    }
    
    free(recent_flows);
    free(ebpf_flows);
    free(gt_flows);

    keep_running = 0;
    pthread_join(epoch_thread, NULL);

    bpf_link__destroy(link);
    twofa_epoch_ebpf__destroy(skel);
    HashMap_destroy(ground_truth);
    return 0;
}