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
#include "elastic_sketch_common.h"
#include "elastic_sketch_ebpf.skel.h"

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

uint32_t HashMap_get(HashMap* map, const uint8_t* key) {
    uint32_t index = hash_key(key);
    HashEntry* entry = map->buckets[index];
    
    while (entry) {
        if (memcmp(entry->key, key, KEY_LEN) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return 0;
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

#define FASTHASH_MIX(h) ({          \
    (h) ^= (h) >> 23;               \
    (h) *= 0x2127599bf4325c37ULL;   \
    (h) ^= (h) >> 47; })

static inline uint64_t fasthash64(const void *buf, size_t len, uint64_t seed) {
    const uint64_t m = 0x880355f21e6d1965ULL;
    const uint8_t *data = (const uint8_t *)buf;
    const uint8_t *end = data + (len & ~7);
    uint64_t h = seed ^ (len * m);
    uint64_t v;

    while (data != end) {
        v = *((uint64_t*)data);
        h ^= FASTHASH_MIX(v);
        h *= m;
        data += 8;
    }

    v = 0;
    switch (len & 7) {
        case 7: v ^= ((uint64_t)data[6]) << 48;
        case 6: v ^= ((uint64_t)data[5]) << 40;
        case 5: v ^= ((uint64_t)data[4]) << 32;
        case 4: v ^= ((uint64_t)data[3]) << 24;
        case 3: v ^= ((uint64_t)data[2]) << 16;
        case 2: v ^= ((uint64_t)data[1]) << 8;
        case 1: v ^= ((uint64_t)data[0]);
            h ^= FASTHASH_MIX(v);
            h *= m;
    }

    return FASTHASH_MIX(h);
}

static inline uint32_t fasthash32(const void *buf, size_t len, uint64_t seed) {
    uint64_t h = fasthash64(buf, len, seed);
    return (uint32_t)(h - (h >> 32));
}

typedef struct {
    uint32_t fp;
    uint32_t count;
} FlowResult;

int cmp_flows(const void* a, const void* b) {
    return ((FlowResult*)b)->count - ((FlowResult*)a)->count;
}

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s -i <interface> -t <pcap_file> [-k <topk>] [-D <duration>] [-T <threshold>]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <interface>   Network interface to attach XDP (required)\n");
    fprintf(stderr, "  -t <pcap_file>   PCAP file for ground truth (required)\n");
    fprintf(stderr, "  -k <topk>        Top-K flows to report (default: 1000)\n");
    fprintf(stderr, "  -D <duration>    Duration in seconds (default: 10, use 0 for auto-detect)\n");
    fprintf(stderr, "  -T <threshold>   Lambda (λ) eviction threshold (default: 8)\n");
    fprintf(stderr, "                   Higher values protect heavy flows more (harder to evict)\n");
    fprintf(stderr, "                   Lower values allow more dynamic adaptation (easier to evict)\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -k 500 -D 10\n", prog);
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -D 0  # Auto-detect mode\n", prog);
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -T 16  # More protective (λ=16)\n", prog);
    fprintf(stderr, "  %s -i veth-recv -t packets.pcap -T 4   # More aggressive (λ=4)\n", prog);
}

int main(int argc, char** argv) {
    const char* ifname = NULL;
    const char* pcap_file = NULL;
    int top_k = 1000;
    int duration = 10;
    int threshold = 2;  
    int opt;

    while ((opt = getopt(argc, argv, "i:t:k:D:T:h")) != -1) {
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
            case 'T':
                threshold = atoi(optarg);
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

    printf("=== ElasticSketch eBPF Test ===\n");
    printf("Interface: %s\n", ifname);
    printf("PCAP: %s\n", pcap_file);
    printf("Top-K: %d\n", top_k);
    printf("Lambda (threshold): %d\n", threshold);
    printf("Duration: %s\n\n", duration == 0 ? "Auto-detect" : "Fixed");
    
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
    struct elastic_sketch_ebpf* skel = elastic_sketch_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load eBPF\n");
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    int sketch_fd = bpf_map__fd(skel->maps.sketch_map);
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        elastic_sketch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    
    struct ElasticSketch sk = {};
    sk.hp.bucket_num = MAX_BUCKETS;
    sk.lp.cell_num = LIGHT_PART_CELLS;
    sk.lp.fasthash_seed = DEFAULT_FASTHASH_SEED;
    sk.threshold = threshold;  
    
    
    for (int i = 0; i < MAX_BUCKETS; i++) {
        for (int j = 0; j < COUNTER_PER_BUCKET; j++) {
            sk.hp.buckets[i].slots[j].fp = 0;
            sk.hp.buckets[i].slots[j].value = 0;
        }
    }
    
    
    for (int i = 0; i < LIGHT_PART_CELLS; i++) {
        sk.lp.cells[i] = 0;
    }
    
    uint32_t map_key = 0;
    if (bpf_map_update_elem(sketch_fd, &map_key, &sk, BPF_ANY) != 0) {
        perror("Failed to init sketch");
        elastic_sketch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    struct bpf_link* link = bpf_program__attach_xdp(skel->progs.xdp_collect_elastic, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP\n");
        elastic_sketch_ebpf__destroy(skel);
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
    printf("   In another terminal, run:\n");
    printf("   sudo tcpreplay --intf1=<replay_interface> %s\n\n", pcap_file);
    
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
                    printf("   Traffic detected! Processing...\n");
                }
                
                if (total != prev_total) {
                    printf("\r   Packets processed: %lu (+%lu/s)    ", 
                           total, total - prev_total);
                    fflush(stdout);
                    prev_total = total;
                    idle_count = 0;
                } else if (started && total > 0) {
                    idle_count++;
                    
                    if (duration == 0 && idle_count >= IDLE_THRESHOLD) {
                        clock_gettime(CLOCK_MONOTONIC, &end_time);
                        printf("\n   Traffic stopped. Processing complete.\n");
                        break;
                    }
                }
                
                if (duration > 0 && started && elapsed_time >= duration) {
                    clock_gettime(CLOCK_MONOTONIC, &end_time);
                    printf("\n   Duration complete.\n");
                    break;
                }
            }
        }
        
        if (!started && elapsed_time >= 60) {
            printf("\n   Timeout: No traffic detected for 60 seconds. Exiting.\n");
            bpf_link__destroy(link);
            elastic_sketch_ebpf__destroy(skel);
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
        
        printf("   === HASH VERIFICATION ===\n");
        printf("   Using: FastHash64 (signature: 0x%08X, seed: 0xCAFEBABE)\n", vals[0]);
        printf("   Sample bucket pos: %u, light pos: %u\n", vals[1], vals[2]);
        printf("   =========================\n\n");
    }
    
    
    printf("[4/4] Analyzing results...\n");
    if (bpf_map_lookup_elem(sketch_fd, &map_key, &sk) != 0) {
        fprintf(stderr, "Failed to read sketch\n");
        bpf_link__destroy(link);
        elastic_sketch_ebpf__destroy(skel);
        HashMap_destroy(ground_truth);
        return 1;
    }
    
    printf("   eBPF stats: evictions=%u, total_inserts=%u\n", sk.hp.cnt, sk.hp.cnt_all);
    
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
            __u32 fp = sk.hp.buckets[i].slots[j].fp;
            __u32 value = sk.hp.buckets[i].slots[j].value;
            
            if (fp != 0 && GetCounterVal(value) > 0) {
                
                uint32_t light_count = 0;
                uint32_t h = fasthash32(&fp, sizeof(__u32), sk.lp.fasthash_seed);
                uint32_t pos = h % sk.lp.cell_num;
                if (pos < LIGHT_PART_CELLS) {
                    light_count = sk.lp.cells[pos];
                }
                
                ebpf_flows[ebpf_count].fp = fp;
                ebpf_flows[ebpf_count].count = GetCounterVal(value) + light_count;
                ebpf_count++;
            }
        }
    }
    
    qsort(ebpf_flows, ebpf_count, sizeof(FlowResult), cmp_flows);
    printf("   eBPF detected: %d flows\n\n", ebpf_count);
    
    printf("Top 10 eBPF Fingerprints (heavy + light):\n");
    for (int i = 0; i < 10 && i < ebpf_count; i++) {
        printf("  %u (0x%08X) -> %u packets\n", 
               ebpf_flows[i].fp, ebpf_flows[i].fp, ebpf_flows[i].count);
    }
    
    
    FlowResult* gt_flows = malloc(ground_truth->size * sizeof(FlowResult));
    int gt_count = 0;
    
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        HashEntry* entry = ground_truth->buckets[i];
        while (entry) {
            uint32_t hash = 0x811C9DC5u; 
            for (int k = 0; k < KEY_LEN; k++) {
                hash ^= entry->key[k];
                hash *= 0x01000193u;  
            }
            
            gt_flows[gt_count].fp = hash;
            gt_flows[gt_count].count = entry->value;
            gt_count++;
            entry = entry->next;
        }
    }
    
    qsort(gt_flows, gt_count, sizeof(FlowResult), cmp_flows);

    printf("\nTop 10 Ground Truth fingerprints:\n");
    for (int i = 0; i < 10 && i < gt_count; i++) {
        printf("  %u (0x%08X) -> %u packets\n", 
               gt_flows[i].fp, gt_flows[i].fp, gt_flows[i].count);
    }
    
    int compare_count = (top_k < ebpf_count) ? top_k : ebpf_count;
    int accepted = 0;
    double sum_are = 0, sum_aae = 0;
    int true_positives = 0;  
    int false_positives = 0; 
    int collision_count = 0; 
    
    int gt_topk_count = (top_k < gt_count) ? top_k : gt_count;
    
    printf("\n=== Per-Flow Comparison (Top-%d) ===\n", top_k);
    for (int i = 0; i < compare_count; i++) {
        uint32_t fp = ebpf_flows[i].fp;
        uint32_t ebpf_cnt = ebpf_flows[i].count;
        
        uint32_t gt_cnt = 0;
        int gt_rank = -1;
        for (int j = 0; j < gt_count; j++) {
            if (gt_flows[j].fp == fp) {
                gt_cnt = gt_flows[j].count;
                gt_rank = j;
                break;
            }
        }
        
        if (gt_cnt > 0) {
            int error = abs((int)ebpf_cnt - (int)gt_cnt);
            double relative_error = (double)error / gt_cnt;
            sum_aae += error;
            sum_are += relative_error;
            
            if (gt_rank < gt_topk_count) {
                true_positives++;
            } else {
                false_positives++;
            }
            
            if (error <= gt_cnt * 0.5) {
                accepted++;
            }
            
            if (relative_error > 1.0) {
                collision_count++;
            }
            
            if (i < 10) {
                printf("  [%d] FP=0x%08X eBPF=%u GT=%u (rank=%d) Error=%d (%.2f%%)%s\n", 
                       i, fp, ebpf_cnt, gt_cnt, gt_rank, error, relative_error * 100,
                       relative_error > 1.0 ? " [COLLISION?]" : "");
            }
        } else {
            false_positives++;
            if (i < 10) {
                printf("  [%d] FP=0x%08X eBPF=%u GT=NOT_FOUND [FALSE POSITIVE]\n", 
                       i, fp, ebpf_cnt);
            }
        }
    }
    
    int false_negatives = 0;
    for (int i = 0; i < gt_topk_count; i++) {
        uint32_t gt_fp = gt_flows[i].fp;
        int found = 0;
        for (int j = 0; j < compare_count; j++) {
            if (ebpf_flows[j].fp == gt_fp) {
                found = 1;
                break;
            }
        }
        if (!found) {
            false_negatives++;
        }
    }
    
    double precision = (true_positives + false_positives) > 0 ? 
                       (double)true_positives / (true_positives + false_positives) : 0;
    double recall = (true_positives + false_negatives) > 0 ?
                    (double)true_positives / (true_positives + false_negatives) : 0;
    double f1_score = (precision + recall) > 0 ?
                      2 * (precision * recall) / (precision + recall) : 0;
    
    printf("\n=== RESULTS ===\n");
    printf("eBPF Flows: %d\n", ebpf_count);
    printf("GT Top-%d Flows: %d\n", top_k, gt_topk_count);
    printf("Compared: %d\n\n", compare_count);
    
    printf("Accuracy Metrics:\n");
    printf("  Accepted (within 50%% error): %d/%d (%.2f%%)\n", 
           accepted, compare_count, 100.0 * accepted / compare_count);
    printf("  ARE (Average Relative Error): %.2f%%\n", 100.0 * sum_are / compare_count);
    printf("  AAE (Average Absolute Error): %.2f packets\n\n", sum_aae / compare_count);
    
    printf("Classification Metrics (Top-%d):\n", top_k);
    printf("  True Positives:  %d\n", true_positives);
    printf("  False Positives: %d\n", false_positives);
    printf("  False Negatives: %d\n", false_negatives);
    printf("  Precision: %.2f%%\n", 100.0 * precision);
    printf("  Recall:    %.2f%%\n", 100.0 * recall);
    printf("  F1 Score:  %.2f%%\n\n", 100.0 * f1_score);
    
    printf("Analysis:\n");
    printf("  Likely Collisions: %d flows (%.1f%%)\n", 
           collision_count, 100.0 * collision_count / compare_count);
    printf("  Note: Using FNV-1a hash over full 13-byte flow key (5-tuple)\n");
    printf("        Collisions are rare with this approach\n");
    
    
    free(ebpf_flows);
    free(gt_flows);
    bpf_link__destroy(link);
    elastic_sketch_ebpf__destroy(skel);
    HashMap_destroy(ground_truth);
    return 0;
}