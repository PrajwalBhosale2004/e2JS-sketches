#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <math.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "persistent_parameters.h"

static int ifindex = -1;
static struct bpf_link *xdp_link = NULL;
static char pin_dir[256] = {0};
static volatile sig_atomic_t exiting = 0;
uint32_t packets_per_window = 0;



typedef struct persistent_pair{
    uint8_t key[KEY_SIZE];
    uint16_t count; 
    int persistence_score;
    uint64_t flow_size;
    uint32_t duration;
} persistent_pair_t;


typedef struct ht_entry{
    uint8_t key[KEY_SIZE];
    uint32_t persistence;
    uint64_t flow_size;
    uint16_t first_seen_window_id;
    uint16_t last_seen_window_id;
    struct ht_entry *next;
} ht_entry_t;

typedef struct hash_table{
    ht_entry_t **buckets;
    size_t n_buckets;
    size_t n_entries;
} ht_t;

static inline double now_seconds(void){
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0){
        return 0.0;
    }
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}


static inline uint32_t mix32_key(const uint8_t key[KEY_SIZE]){
    uint32_t h = 2166136261u;
    for (int i = 0; i < KEY_SIZE; ++i){
        uint32_t v = key[i];
        h ^= v;
        h *= 16777619u;
        h = (h << 13) | (h >> 19);
        h += 0x9e3779b9u;
    }
    return h;
}

static size_t next_pow2(size_t x){
    size_t p = 1;
    while (p < x)
        p <<= 1;
    return p;
}

int ht_init_with_hint(ht_t *ht, size_t expected_keys){
    if(!ht) return -1;
    size_t buckets = next_pow2((expected_keys > 0 ? (expected_keys * 2) : 1024));
    if(buckets < 1024) buckets = 1024;
    ht->n_buckets = buckets;
    ht->buckets = (ht_entry_t **)calloc(ht->n_buckets, sizeof(ht_entry_t *));
    if(!ht->buckets) return -1;
    ht->n_entries = 0;
    return 0;
}

void ht_free(ht_t *ht){
    if(!ht || !ht->buckets) return;
    for (size_t i = 0; i < ht->n_buckets; ++i){
        ht_entry_t *e = ht->buckets[i];
        while (e){
            ht_entry_t *n = e->next;
            free(e);
            e = n;
        }
    }
    free(ht->buckets);
    ht->buckets = NULL;
    ht->n_buckets = 0;
    ht->n_entries = 0;
}

void ht_increment_persistence(ht_t *ht, const uint8_t key[KEY_SIZE]){
    if(!ht || !ht->buckets) return;

    uint32_t h = mix32_key(key);
    size_t idx = (size_t)h & (ht->n_buckets - 1);

    ht_entry_t *e = ht->buckets[idx];
    while (e){
        if(memcmp(e->key, key, KEY_SIZE) == 0){
            e->persistence++;
            return;
        }
        e = e->next;
    }

    ht_entry_t *ne = malloc(sizeof(*ne));
    if(!ne)
        return;

    memcpy(ne->key, key, KEY_SIZE);
    ne->persistence = 1;
    ne->next = ht->buckets[idx];
    ht->buckets[idx] = ne;
    ht->n_entries++;
}



static void combine_key(uint8_t key[KEY_SIZE], uint32_t index, uint16_t fingerprint, uint64_t residual_part[2]){
    residual_part[1] = ((residual_part[1] << 16) + fingerprint) * BUCKET_NUM + index;
    uint32_t temp_parts[2] = {0};
    temp_parts[0] = (residual_part[0] >> 52) + ((residual_part[1] >> 26) << 12);
    temp_parts[1] = residual_part[1] & 0x3FFFFFF;

    temp_parts[1] = ((temp_parts[1] & 0x1FFF) ^ (temp_parts[1] >> 13)) + (temp_parts[1] & (~0x1FFF));

    uint64_t part1 = residual_part[0] & MI_MASK;
    uint64_t part2 = 0;

    part2 += temp_parts[1] ^ temp_parts[0];
    part2 <<= 26;
    part2 += temp_parts[0] ^ (uint32_t)(part1 & MASK_26BITS) ^ (uint32_t)(part1 >> 26);

    part1 = (part1 * MI_A_INV) & MI_MASK;
    part2 = (part2 * MI_A_INV) & MI_MASK;

    residual_part[0] = part1 + ((part2 & 0xfff) << 52);
    residual_part[1] = part2 >> 12;
    memcpy(key, residual_part, KEY_SIZE);
}


static uint8_t get_residual_part_field_from_al(int aux_fd, uint32_t slot_index, uint64_t residual_part[2]){
    uint32_t slot_length = RESIDUAL_PART_BITS + SIGNAL_BITS;
    uint32_t bit_idx = slot_index * slot_length;
    uint32_t slot_word_idx = bit_idx / 64;
    uint32_t slot_bit_idx_in_word = bit_idx % 64;

    uint32_t extracted_bits = 0;
    uint32_t rp_word_idx = 0;
    uint32_t rp_bit_in_word = 0;

    residual_part[0] = 0;
    residual_part[1] = 0;

    while (extracted_bits < slot_length && slot_word_idx < AUX_LIST_WORDS){
        uint64_t aux_val = 0;

        if(bpf_map_lookup_elem(aux_fd, &slot_word_idx, &aux_val) != 0) break;

        uint32_t to_extract = slot_length - extracted_bits;
        if(to_extract > (64 - rp_bit_in_word)) to_extract = 64 - rp_bit_in_word;
        if(to_extract > (64 - slot_bit_idx_in_word)) to_extract = 64 - slot_bit_idx_in_word;

        uint64_t extract_part;
        if(to_extract == 64) extract_part = aux_val;

        else{
            uint64_t mask = (((uint64_t)1) << to_extract) - 1;
            extract_part = (aux_val >> slot_bit_idx_in_word) & mask;
        }

        if(rp_bit_in_word == 0 && rp_word_idx < 2)residual_part[rp_word_idx] = 0;
        
        if(rp_word_idx < 2) residual_part[rp_word_idx] += extract_part << rp_bit_in_word;

        bit_idx += to_extract;
        slot_word_idx = bit_idx / 64;
        slot_bit_idx_in_word = bit_idx % 64;
        extracted_bits += to_extract;
        rp_word_idx = extracted_bits / 64;
        rp_bit_in_word = extracted_bits % 64;
    }

    uint8_t counter = 0;
    if(rp_word_idx < 2 && rp_bit_in_word >= 2){
        counter = residual_part[rp_word_idx] >> (rp_bit_in_word - 2);
        uint64_t clear_mask = ~(((uint64_t)3) << (rp_bit_in_word - 2));
        residual_part[rp_word_idx] &= clear_mask;
    }

    return counter & 0x3;
}


static int read_persistent_items(int persistent_fd, int aux_fd, persistent_pair_t **out_pairs, size_t *out_n){
    ht_t merge_ht;
    if(ht_init_with_hint(&merge_ht, BUCKET_NUM * CELL_NUM_H) != 0){
        fprintf(stderr, "Failed to init merge hash table\n");
        return -1;
    }

    for (uint32_t bucket_idx = 0; bucket_idx < BUCKET_NUM; bucket_idx++){
        struct persistent_bucket bucket;

        if(bpf_map_lookup_elem(persistent_fd, &bucket_idx, &bucket) != 0) continue;

        for (int cell_idx = 0; cell_idx < CELL_NUM_H; cell_idx++){
            if(bucket.cells[cell_idx].window_count == 0)
                continue;

            uint32_t slot_index = bucket_idx * CELL_NUM_H + cell_idx;
            uint64_t residual_part[2] = {0, 0};
            get_residual_part_field_from_al(aux_fd, slot_index, residual_part);

            uint8_t key[KEY_SIZE];
            combine_key(key, bucket_idx, bucket.cells[cell_idx].fp, residual_part);

            uint32_t h = mix32_key(key);
            size_t bidx = h & (merge_ht.n_buckets - 1);

            ht_entry_t *e = merge_ht.buckets[bidx];
            while (e){
                if(memcmp(e->key, key, KEY_SIZE) == 0) break;
                e = e->next;
            }

            if(!e){
                ht_entry_t *ne = calloc(1, sizeof(*ne));
                memcpy(ne->key, key, KEY_SIZE);
                ne->persistence = bucket.cells[cell_idx].window_count;
                ne->flow_size = bucket.cells[cell_idx].flow_size;
                ne->first_seen_window_id = bucket.cells[cell_idx].first_seen_window_id;
                ne->last_seen_window_id = bucket.cells[cell_idx].last_seen_window_id;
                ne->next = merge_ht.buckets[bidx];
                merge_ht.buckets[bidx] = ne;
                merge_ht.n_entries++;
            }
            else{
                if(bucket.cells[cell_idx].window_count > e->persistence) e->persistence = bucket.cells[cell_idx].window_count;
                e->flow_size += bucket.cells[cell_idx].flow_size;
                
                if (bucket.cells[cell_idx].first_seen_window_id < e->first_seen_window_id) e->first_seen_window_id = bucket.cells[cell_idx].first_seen_window_id;
            
                if (bucket.cells[cell_idx].last_seen_window_id > e->last_seen_window_id) e->last_seen_window_id = bucket.cells[cell_idx].last_seen_window_id;
            }
        }
    }

    persistent_pair_t *pairs = calloc(merge_ht.n_entries, sizeof(persistent_pair_t));
    if(!pairs){
        ht_free(&merge_ht);
        return -1;
    }

    size_t written = 0;
    for (size_t i = 0; i < merge_ht.n_buckets && written < merge_ht.n_entries; ++i){
        ht_entry_t *e = merge_ht.buckets[i];
        while (e && written < merge_ht.n_entries){
            memcpy(pairs[written].key, e->key, KEY_SIZE);
            pairs[written].count = e->persistence;
            pairs[written].persistence_score = e->persistence;
            pairs[written].flow_size = e->flow_size;
            pairs[written].duration = e->last_seen_window_id - e->first_seen_window_id + 1;

            written++;
            e = e->next;
        }
    }

    printf("Scanned %d buckets with %d heavy cells each, collected %zu unique flows\n", BUCKET_NUM, CELL_NUM_H, written);

    ht_free(&merge_ht);

    *out_pairs = pairs;
    *out_n = written;
    return 0;
}


static void print_persistent_flows(persistent_pair_t *pairs, size_t n_pairs, int min_windows){
    printf("\nPersistent Items (appearing in %d+ windows):\n", min_windows);
    printf("%-4s %-16s %-7s %-16s %-7s %-6s %-10s %-10s %-10s %-10s\n",
           "No", "Src IP", "S.Port", "Dst IP", "D.Port", "Proto", "Windows", "Flow Size (bytes)", "Duration", "Rate (bytes/windows)");
    printf("----------------------------------------------------------------------------------------------------------------\n");

    int persistent_count = 0;
    for (size_t i = 0; i < n_pairs; i++){
        if(pairs[i].persistence_score < min_windows) continue;

        persistent_count++;
        uint8_t *p = pairs[i].key;

        char src_ip[16], dst_ip[16];
        snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
        snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u", p[4], p[5], p[6], p[7]);

        uint16_t src_port = (p[8] << 8) | p[9];
        uint16_t dst_port = (p[10] << 8) | p[11];
        uint8_t proto = p[12];

        const char *proto_name = "???";
        if(proto == 6) proto_name = "TCP";
        else if(proto == 17) proto_name = "UDP";
        else if(proto == 1) proto_name = "ICMP";

        double flow_size_display;
        const char *size_unit;
        if (pairs[i].flow_size < 1024) {
            flow_size_display = pairs[i].flow_size;
            size_unit = "B";
        } else if (pairs[i].flow_size < 1024*1024) {
            flow_size_display = pairs[i].flow_size / 1024.0;
            size_unit = "KB";
        } else if (pairs[i].flow_size < 1024*1024*1024) {
            flow_size_display = pairs[i].flow_size / (1024.0 * 1024.0);
            size_unit = "MB";
        } else {
            flow_size_display = pairs[i].flow_size / (1024.0 * 1024.0 * 1024.0);
            size_unit = "GB";
        }

        printf("%-4d %-16s %-7u %-16s %-7u %-6s %-10u %8.2f %-8s %-10u %-10.2f\n",
            persistent_count, src_ip, src_port, dst_ip, dst_port,
            proto_name, pairs[i].count, flow_size_display, size_unit, pairs[i].duration, pairs[i].flow_size / (double)pairs[i].duration);
    }

    if(persistent_count == 0) printf("No persistent flows found.\n");
    
    printf("----------------------------------------------------------------------------------------------------------------\n");
    printf("Total persistent flows: %d\n", persistent_count);
}


static int pair_persist_cmp_desc(const void *a, const void *b){
    const persistent_pair_t *pa = a, *pb = b;
    if(pa->persistence_score > pb->persistence_score) return -1;
    if(pa->persistence_score < pb->persistence_score) return 1;
    if(pa->count > pb->count) return -1;
    if(pa->count < pb->count) return 1;
    return 0;
}

static int read_xdp_stats(int stats_fd, __u64 *total_packets, __u64 *total_bytes){
    __u32 key = 0;
    struct xdp_stats values[128];

    memset(values, 0, sizeof(values));

    if(bpf_map_lookup_elem(stats_fd, &key, values) != 0){
        fprintf(stderr, "Failed to read XDP stats: %s\n", strerror(errno));
        return -1;
    }

    *total_packets = 0;
    *total_bytes = 0;

    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if(num_cpus > 128) num_cpus = 128;

    for (int i = 0; i < num_cpus; i++){
        *total_packets += values[i].rx_packets;
        *total_bytes += values[i].rx_bytes;
    }

    return 0;
}

static void print_throughput_stats(__u64 packets, __u64 bytes, double elapsed_seconds){
    const double ELAPSE_EPS = 1e-9;
    if(elapsed_seconds <= ELAPSE_EPS) elapsed_seconds = ELAPSE_EPS;
    
    double pps = (double)packets / elapsed_seconds;
    double mpps = pps / 1e6;

    double bps = (double)bytes / elapsed_seconds;
    double mbps = (bps * 8.0) / 1e6;
    double gbps = mbps / 1e3;

    double avg_pkt_size = packets > 0 ? (double)bytes / (double)packets : 0;

    printf("\n=== Throughput Statistics ===\n");
    printf("Total packets processed: %llu\n", packets);
    printf("Total bytes processed: %llu (%.2f MB)\n", bytes, (double)bytes / (1024.0 * 1024.0));
    printf("Average packet size: %.1f bytes\n", avg_pkt_size);
    printf("Collection duration: %.2f seconds\n", elapsed_seconds);
    printf("Packet rate: %.2f Mpps (%.2f Kpps)\n", mpps, pps / 1000.0);
    printf("Throughput: %.2f Mbps (%.3f Gbps)\n", mbps, gbps);
}

size_t build_persistent_ground_truth(ht_t *gt, const char *trace_file, uint32_t ppw){
    FILE *f = fopen(trace_file, "rb");
    if(!f){
        perror("fopen");
        return 0;
    }

    fseek(f, 0, SEEK_END);
    size_t total_items = ftell(f) / KEY_SIZE;
    rewind(f);

    size_t window_size = ppw;
    ht_init_with_hint(gt, total_items / 10);

    ht_t window_ht = {0};
    ht_init_with_hint(&window_ht, window_size);

    uint8_t buf[KEY_SIZE];
    size_t epoch = 0;

    for (size_t i = 0; i < total_items; i++){
        size_t n = fread(buf, 1, KEY_SIZE, f);
        if(n != KEY_SIZE){
            fprintf(stderr, "fread failed or reached EOF (read %zu bytes)\n", n);
            break;
        }
        epoch++;

        
        uint32_t h = mix32_key(buf);
        size_t idx = h & (window_ht.n_buckets - 1);

        ht_entry_t *e = window_ht.buckets[idx];
        int found = 0;
        while (e){
            if(!memcmp(e->key, buf, KEY_SIZE)){
                found = 1;
                break;
            }
            e = e->next;
        }

        if(!found){
            ht_entry_t *ne = malloc(sizeof(*ne));
            memcpy(ne->key, buf, KEY_SIZE);
            ne->persistence = 1;
            ne->next = window_ht.buckets[idx];
            window_ht.buckets[idx] = ne;
            window_ht.n_entries++;
        }

        
        if((epoch % window_size) == 0){
            for (size_t b = 0; b < window_ht.n_buckets; b++){
                ht_entry_t *w = window_ht.buckets[b];
                while (w){
                    ht_increment_persistence(gt, w->key);
                    w = w->next;
                }
            }
            ht_free(&window_ht);
            ht_init_with_hint(&window_ht, window_size);
        }
    }

    
    for (size_t b = 0; b < window_ht.n_buckets; b++){
        ht_entry_t *w = window_ht.buckets[b];
        while (w){
            ht_increment_persistence(gt, w->key);
            w = w->next;
        }
    }

    ht_free(&window_ht);
    fclose(f);

    return total_items;
}

static void int_exit(int sig){
    exiting = 1;
}


static void compute_persistent_metrics(persistent_pair_t *est, size_t n_est,ht_t *gt, size_t num_windows, int min_windows){
    size_t tp = 0, est_p = 0, true_p = 0;
    double aae_sum = 0.0, are_sum = 0.0;

    
    for (size_t i = 0; i < gt->n_buckets; i++){
        for (ht_entry_t *e = gt->buckets[i]; e; e = e->next){
            if(e->persistence >= (size_t)min_windows)
                true_p++;
        }
    }

    
    for (size_t i = 0; i < n_est; i++){
        if(est[i].persistence_score >= min_windows)
            est_p++;
    }

    
    for (size_t i = 0; i < n_est; i++){
        if(est[i].persistence_score < min_windows)
            continue;

        uint32_t true_persistence = 0;
        uint32_t h = mix32_key(est[i].key);
        size_t idx = h & (gt->n_buckets - 1);

        for (ht_entry_t *e = gt->buckets[idx]; e; e = e->next){
            if(memcmp(e->key, est[i].key, KEY_SIZE) == 0){
                true_persistence = e->persistence;
                break;
            }
        }

        if(true_persistence >= (size_t)min_windows){
            tp++;

            double diff = fabs((double)est[i].persistence_score - (double)true_persistence);

            aae_sum += diff;

            if(true_persistence > 0){
                are_sum += diff / (double)true_persistence;
            }
        }
    }

    double precision = est_p ? (double)tp / est_p : 0.0;
    double recall = true_p ? (double)tp / true_p : 0.0;
    double f1_score = (precision + recall) > 0 ? 2.0 * (precision * recall) / (precision + recall) : 0.0;
    double aae = tp ? aae_sum / tp : 0.0;
    double are = tp ? are_sum / tp : 0.0;

    printf("\n=== Persistent Detection Metrics ===\n");
    printf("Actual persistent flows   : %zu\n", true_p);
    printf("Estimated persistent flows: %zu\n", est_p);
    printf("True positives            : %zu\n", tp);
    printf("Precision                 : %.3f\n", precision);
    printf("Recall                    : %.3f\n", recall);
    printf("F1 Score                  : %.3f\n", f1_score);
    printf("ARE                       : %.3f\n", are);
    printf("AAE                       : %.3f\n", aae);

    
    double bucket_mem = BUCKET_NUM * (CELL_NUM_H + CELL_NUM_L) * (2 + 2 + 2);
    double aux_mem = AUX_LIST_WORDS * 8;
    double total_mem = bucket_mem + aux_mem;
    printf("Memory used: %.2f KB (buckets: %.2f KB, auxiliary list: %.2f KB)\n", total_mem / 1024.0, bucket_mem / 1024.0, aux_mem / 1024.0);
}

static void usage(const char *prog){
    fprintf(stderr,
            "Usage: %s -i <iface> -o <pin_dir> [-k topK] [-D duration] [-p persistence_threshold] [-t trace_file] <bpf_obj>\n"
            " -i <iface>       network interface to attach XDP program\n"
            " -o <pin_dir>     bpffs pin directory (must exist) where maps will be pinned\n"
            " -k <topK>        top-K to print (default 50)\n"
            " -D <duration>    duration seconds for collection of data (default 10)\n"
            " -p <threshold>   persistence threshold: min windows to be considered persistent (default 3)\n"
            " -t <trace_file>  optional trace file for ground truth comparison\n"
            " <bpf_obj>        compiled BPF object (persistent_ebpf.o)\n",
            prog);
}

int main(int argc, char **argv){
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *map;
    const char *iface = NULL;
    const char *obj_file = NULL;
    const char *trace_file = NULL;
    int duration = 10;
    int topK = 50;
    int opt;

    while ((opt = getopt(argc, argv, "i:o:D:k:t:")) != -1){
        switch (opt){
        case 'i':
            iface = optarg;
            break;
        case 'o':
            snprintf(pin_dir, sizeof(pin_dir), "%s", optarg);
            break;
        case 'D':
            duration = atoi(optarg);
            break;
        case 'k':
            topK = atoi(optarg);
            break;
        case 't':
            trace_file = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if(!iface || !pin_dir[0] || optind >= argc){
        usage(argv[0]);
        return 1;
    }

    obj_file = argv[optind];

    ifindex = if_nametoindex(iface);
    if(!ifindex){
        perror("if_nametoindex");
        return 1;
    }

    
    ht_t gt_ht = {0};
    size_t n_trace_items = 0;

    if(trace_file){
        FILE *f = fopen(trace_file, "rb");
        fseek(f, 0, SEEK_END);
        size_t total_items = ftell(f) / KEY_SIZE;
        fclose(f);

        packets_per_window = (total_items + NUM_WINDOWS - 1) / NUM_WINDOWS;
        printf("Building ground-truth from %s....\n", trace_file);

        n_trace_items = build_persistent_ground_truth(&gt_ht, trace_file, packets_per_window);
        printf("Ground truth: %zu packets, %zu flows, %u windows\n", n_trace_items, gt_ht.n_entries, NUM_WINDOWS);
        printf("Inferred packets per window: %u\n", packets_per_window);
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    obj = bpf_object__open_file(obj_file, NULL);
    if(libbpf_get_error(obj)){
        fprintf(stderr, "ERROR: failed to open BPF object\n");
        ht_free(&gt_ht);
        return 1;
    }

    if(bpf_object__load(obj)){
        fprintf(stderr, "ERROR: failed to load BPF object\n");
        ht_free(&gt_ht);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "persistent_xdp");
    if(!prog){
        fprintf(stderr, "ERROR: XDP program 'persistent_xdp' not found\n");
        ht_free(&gt_ht);
        return 1;
    }

    if(trace_file){
        map = bpf_object__find_map_by_name(obj, "packets_per_window_map");
        if(map){
            int ppw_fd = bpf_map__fd(map);
            uint32_t ppw_key = 0;
            bpf_map_update_elem(ppw_fd, &ppw_key, &packets_per_window, BPF_ANY);
            printf("Set packets_per_window in BPF map: %u\n", packets_per_window);
        }
    }

    xdp_link = bpf_program__attach_xdp(prog, ifindex);
    if(!xdp_link){
        fprintf(stderr, "ERROR: failed to attach XDP program\n");
        ht_free(&gt_ht);
        return 1;
    }

    printf("Persistent Item Detection XDP attached on %s (ifindex %d)\n", iface, ifindex);
    printf("Configuration:\n");
    printf("  Buckets: %d\n", BUCKET_NUM);
    printf("  Cells per bucket: %d heavy + %d light = %d total\n",
           CELL_NUM_H, CELL_NUM_L, CELL_NUM_H + CELL_NUM_L);
    printf("  Packets per window: %u\n", packets_per_window);
    printf("  Tracked windows: %d\n", 8);
    printf("  Persistence threshold: %.2f windows\n", NUM_WINDOWS*PERSISTENCE_THRESHOLD);

    double bucket_mem = BUCKET_NUM * sizeof(struct persistent_bucket);
    double aux_mem = AUX_LIST_WORDS * 8;
    double total_mem = bucket_mem + aux_mem;
    printf("  Memory used: %.2f KB (%.2f MB)\n", total_mem / 1024.0, total_mem / (1024.0 * 1024.0));
    printf("    - Bucket array: %.2f KB\n", bucket_mem / 1024.0);
    printf("    - Auxiliary list: %.2f KB (%d words)\n", aux_mem / 1024.0, AUX_LIST_WORDS);

    struct stat st;
    if(stat(pin_dir, &st) != 0){
        if(mkdir(pin_dir, 0755) != 0){
            fprintf(stderr, "ERROR: cannot create pin dir %s: %s\n",
                    pin_dir, strerror(errno));
            goto cleanup;
        }
    }

    map = bpf_object__find_map_by_name(obj, "persistent_map");
    bpf_map__pin(map, "/sys/fs/bpf/persistent/persistent_map");

    map = bpf_object__find_map_by_name(obj, "auxiliary_list_map");
    bpf_map__pin(map, "/sys/fs/bpf/persistent/auxiliary_list_map");

    map = bpf_object__find_map_by_name(obj, "packet_sequence_map");
    bpf_map__pin(map, "/sys/fs/bpf/persistent/packet_sequence_map");

    map = bpf_object__find_map_by_name(obj, "xdp_stats_map");
    bpf_map__pin(map, "/sys/fs/bpf/persistent/xdp_stats_map");

    map = bpf_object__find_map_by_name(obj, "packets_per_window_map");
    bpf_map__pin(map, "/sys/fs/bpf/persistent/packets_per_window_map");

    char stats_pin[512];
    snprintf(stats_pin, sizeof(stats_pin), "%s/xdp_stats_map", pin_dir);

    int stats_fd = bpf_obj_get(stats_pin);
    if(stats_fd < 0){
        fprintf(stderr, "Warning: Could not open stats map: %s\n", strerror(errno));
    }

    double start_time = now_seconds();
    printf("\nCollecting data for %d seconds. Press CTRL+C to stop early and print results.\n", duration);

    for (int i = 0; i < duration && !exiting; ++i){
        sleep(1);
        if((i + 1) % 5 == 0 && !exiting){
            printf("Collecting... %d seconds elapsed\n", i + 1);
        }
    }
    double collection_end_time = now_seconds();
    double collection_time = collection_end_time - start_time;

    if(!exiting){
        printf("\n=== Collection complete, reading sketch ===\n");
    }
    else{
        printf("\n=== Collection interrupted, reading sketch ===\n");
    }

    __u64 total_packets = 0;
    __u64 total_bytes = 0;
    if(stats_fd >= 0){
        if(read_xdp_stats(stats_fd, &total_packets, &total_bytes) == 0){
            printf("XDP processed: %llu packets, %llu bytes\n", total_packets, total_bytes);
        }
        else{
            fprintf(stderr, "Warning: Could not read XDP stats\n");
        }
        close(stats_fd);
    }

    char persistent_pin[512];
    snprintf(persistent_pin, sizeof(persistent_pin), "%s/persistent_map", pin_dir);
    char aux_pin[512];
    snprintf(aux_pin, sizeof(aux_pin), "%s/auxiliary_list_map", pin_dir);
    char seq_pin[512];
    snprintf(seq_pin, sizeof(seq_pin), "%s/packet_sequence_map", pin_dir);

    int persistent_fd = bpf_obj_get(persistent_pin);
    if(persistent_fd < 0){
        fprintf(stderr, "ERROR: bpf_obj_get failed for %s: %s\n", persistent_pin, strerror(errno));
        goto cleanup;
    }

    int aux_fd = bpf_obj_get(aux_pin);
    if(aux_fd < 0){
        fprintf(stderr, "ERROR: bpf_obj_get failed for %s: %s\n", aux_pin, strerror(errno));
        close(persistent_fd);
        goto cleanup;
    }

    printf("\nOpened pinned maps: persistent_fd = %d, aux_fd = %d\n", persistent_fd, aux_fd);

    persistent_pair_t *pairs = NULL;
    size_t n_pairs = 0;

    if(read_persistent_items(persistent_fd, aux_fd, &pairs, &n_pairs) != 0){
        fprintf(stderr, "ERROR: read_persistent_items failed\n");
        close(persistent_fd);
        close(aux_fd);
        goto cleanup;
    }

    close(persistent_fd);
    close(aux_fd);
    printf("Recovered %zu flows\n", n_pairs);

    if(n_pairs > 0){
        qsort(pairs, n_pairs, sizeof(persistent_pair_t), pair_persist_cmp_desc);
        int persistence_threshold = NUM_WINDOWS * PERSISTENCE_THRESHOLD;
        print_persistent_flows(pairs, n_pairs, persistence_threshold);

        if(trace_file && gt_ht.n_entries > 0){
            compute_persistent_metrics(pairs, n_pairs, &gt_ht, NUM_WINDOWS, persistence_threshold);
        }

        int k = topK;
        if((size_t)k > n_pairs) k = (int)n_pairs;
        free(pairs);
    }
    else{
        printf("No flows found.\n");
    }

    if(total_packets > 0){
        print_throughput_stats(total_packets, total_bytes, collection_time);
    }

cleanup:
    printf("\nDetaching Persistent Item Detection XDP...\n");
    if(xdp_link){
        bpf_link__destroy(xdp_link);
        xdp_link = NULL;
    }
    if(obj) bpf_object__close(obj);
    
    ht_free(&gt_ht);
    printf("Done.\n");
    return 0;
}