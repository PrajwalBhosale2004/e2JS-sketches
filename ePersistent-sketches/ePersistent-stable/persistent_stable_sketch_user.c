#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "persistent_stable_sketch_common.h"
#include "persistent_stable_sketch_ebpf.skel.h"

#define KEY_SIZE 13
#define DEFAULT_NUM_WINDOWS 1600
#define DEFAULT_THRESHOLD 0.5

static volatile sig_atomic_t exiting = 0;
static struct persistent_stable_sketch_ebpf *skel;
static int sketch_fd;

static void handle_signal(int sig) {
    exiting = 1;
}

typedef struct {
    uint8_t key[KEY_SIZE];
    uint32_t persistence;  // number of windows in which the item appeared
} persistent_pair_t;

typedef struct ht_entry {
    uint8_t key[KEY_SIZE];
    uint32_t persistence;
    struct ht_entry *next;
} ht_entry_t;

typedef struct {
    ht_entry_t **buckets;
    size_t n_buckets;
    size_t n_entries;
} ht_t;

static inline double now_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static inline uint32_t mix32_key(const uint8_t key[KEY_SIZE]) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < KEY_SIZE; ++i) {
        uint32_t v = key[i];
        h ^= v;
        h *= 16777619u;
        h = (h << 13) | (h >> 19);
        h += 0x9e3779b9u;
    }
    return h;
}

static size_t next_pow2(size_t x) {
    size_t p = 1;
    while (p < x) p <<= 1;
    return p;
}

int ht_init_with_hint(ht_t *ht, size_t expected_keys) {
    if (!ht) return -1;
    size_t buckets = next_pow2((expected_keys > 0 ? (expected_keys * 2) : 1024));
    if (buckets < 1024) buckets = 1024;
    ht->n_buckets = buckets;
    ht->buckets = (ht_entry_t**)calloc(ht->n_buckets, sizeof(ht_entry_t *));
    if (!ht->buckets) return -1;
    ht->n_entries = 0;
    return 0;
}

void ht_free(ht_t *ht) {
    if (!ht || !ht->buckets) return;
    for (size_t i = 0; i < ht->n_buckets; ++i) {
        ht_entry_t *e = ht->buckets[i];
        while (e) {
            ht_entry_t *n = e->next;
            free(e);
            e = n;
        }
    }
    free(ht->buckets);
    ht->buckets = NULL;
}

void ht_increment_persistence(ht_t *ht, const uint8_t key[KEY_SIZE]) {
    if (!ht || !ht->buckets) return;
    uint32_t h = mix32_key(key);
    size_t idx = (size_t)h & (ht->n_buckets - 1);
    ht_entry_t *e = ht->buckets[idx];
    
    while (e) {
        if (memcmp(e->key, key, KEY_SIZE) == 0) {
            e->persistence++;
            return;
        }
        e = e->next;
    }
    
    // if not already in the ht, then insert as new entry
    ht_entry_t *ne = (ht_entry_t*)malloc(sizeof(ht_entry_t));
    if (!ne) return;
    memcpy(ne->key, key, KEY_SIZE);
    ne->persistence = 1;
    ne->next = ht->buckets[idx];
    ht->buckets[idx] = ne;
    ht->n_entries++;
}

uint32_t ht_get_persistence(ht_t *ht, const uint8_t key[KEY_SIZE]) {
    if (!ht || !ht->buckets) return 0;
    uint32_t h = mix32_key(key);
    size_t idx = (size_t)h & (ht->n_buckets - 1);
    ht_entry_t *e = ht->buckets[idx];
    
    while (e) {
        if (memcmp(e->key, key, KEY_SIZE) == 0) 
            return e->persistence;
        e = e->next;
    }
    return 0;
}

size_t ht_collect_pairs(ht_t *ht, persistent_pair_t *pairs, size_t capacity) {
    if (!ht || !ht->buckets) return 0;
    size_t written = 0;
    for (size_t i = 0; i < ht->n_buckets && written < capacity; ++i) {
        ht_entry_t *e = ht->buckets[i];
        while (e && written < capacity) {
            memcpy(pairs[written].key, e->key, KEY_SIZE);
            pairs[written].persistence = e->persistence;
            written++;
            e = e->next;
        }
    }
    return written;
}

// Build ground truth with window-based persistence calculation
size_t build_persistent_ground_truth(ht_t *ground_truth, const char *trace_file, 
                                     size_t num_windows) {
    if (!ground_truth || !trace_file) return 0;
    
    FILE *f = fopen(trace_file, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", trace_file, strerror(errno));
        return 0;
    }
    
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    
    long fsz = ftell(f);
    if (fsz <= 0) {
        fclose(f);
        return 0;
    }
    rewind(f);
    
    size_t total_items = (size_t)(fsz / KEY_SIZE);
    if (total_items == 0) {
        fclose(f);
        return 0;
    }
    
    size_t window_size = (total_items / num_windows);
    printf("Total items: %zu, Windows: %zu, Window size: %zu\n", 
           total_items, num_windows, window_size);
    
    if (ht_init_with_hint(ground_truth, total_items / 10) != 0) {
        fprintf(stderr, "ht init failed\n");
        fclose(f);
        return 0;
    }
    
    // temp hash table to track packets in current window--> later used for persistence update
    ht_t current_window_ht = {0};
    if (ht_init_with_hint(&current_window_ht, window_size) != 0) {
        fprintf(stderr, "current window ht init failed\n");
        ht_free(ground_truth);
        fclose(f);
        return 0;
    }
    
    uint8_t buf[KEY_SIZE];
    size_t epoch = 0;
    size_t windows_processed = 0;
    
    printf("Building window-based ground truth...\n");
    
    for (size_t i = 0; i < total_items; ++i) {
        size_t r = fread(buf, 1, KEY_SIZE, f);
        if (r != KEY_SIZE) break;
        
        epoch++;
        
        if ((epoch % window_size) == 0) {
            for (size_t j = 0; j < current_window_ht.n_buckets; ++j) {
                ht_entry_t *e = current_window_ht.buckets[j];
                while (e) {
                    ht_increment_persistence(ground_truth, e->key);
                    e = e->next;
                }
            }
            
            ht_free(&current_window_ht);
            if (ht_init_with_hint(&current_window_ht, window_size) != 0) {
                fprintf(stderr, "Failed to reinit window ht\n");
                break;
            }
            
            windows_processed++;
            if (windows_processed % 200 == 0) {
                printf("  Processed %zu windows...\n", windows_processed);
            }
        } else {
            // Mark item as seen in current window (count once per window)
            uint32_t h = mix32_key(buf);
            size_t idx = (size_t)h & (current_window_ht.n_buckets - 1);
            ht_entry_t *e = current_window_ht.buckets[idx];
            
            int found = 0;
            while (e) {
                if (memcmp(e->key, buf, KEY_SIZE) == 0) {
                    found = 1;
                    break;
                }
                e = e->next;
            }
            
            if (!found) {
                ht_entry_t *ne = (ht_entry_t*)malloc(sizeof(ht_entry_t));
                if (ne) {
                    memcpy(ne->key, buf, KEY_SIZE);
                    ne->persistence = 1;
                    ne->next = current_window_ht.buckets[idx];
                    current_window_ht.buckets[idx] = ne;
                    current_window_ht.n_entries++;
                }
            }
        }
    }
    
    // Process remaining items in last incomplete window
    if (current_window_ht.n_entries > 0) {
        for (size_t j = 0; j < current_window_ht.n_buckets; ++j) {
            ht_entry_t *e = current_window_ht.buckets[j];
            while (e) {
                ht_increment_persistence(ground_truth, e->key);
                e = e->next;
            }
        }
        windows_processed++;
    }
    
    ht_free(&current_window_ht);
    fclose(f);
    
    printf("Ground truth built: %zu unique items across %zu windows\n", 
           ground_truth->n_entries, windows_processed);
    
    return epoch;
}

static int pair_cmp_desc(const void *a, const void *b) {
    const persistent_pair_t *pa = a, *pb = b;
    if (pa->persistence < pb->persistence) return 1;
    if (pa->persistence > pb->persistence) return -1;
    return 0;
}

static int read_sketch_persistent_candidates(struct PersistentStableSketch *psk, 
                                             persistent_pair_t **out_pairs, 
                                             size_t *out_n) {
    size_t max_candidates = MAX_DEPTH * MAX_WIDTH;
    persistent_pair_t *pairs = calloc(max_candidates, sizeof(persistent_pair_t));
    if (!pairs) return -1;
    
    size_t written = 0;
    for (int i = 0; i < psk->depth && i < MAX_DEPTH; i++) {
        for (int j = 0; j < psk->width && j < MAX_WIDTH; j++) {
            struct PersistentSBucket *b = &psk->buckets[i][j];
            if (b->count > 0) {
                memcpy(pairs[written].key, b->key, KEY_SIZE);
                pairs[written].persistence = b->count;
                written++;
            }
        }
    }
    
    *out_pairs = pairs;
    *out_n = written;
    return 0;
}

static void print_flow_key(const uint8_t *k) {
    printf("%u.%u.%u.%u:%-5u -> %u.%u.%u.%u:%-5u proto=%u",
           k[0], k[1], k[2], k[3], (k[8]<<8)|k[9],
           k[4], k[5], k[6], k[7], (k[10]<<8)|k[11], k[12]);
}

static void compute_persistent_metrics(persistent_pair_t *est_pairs, size_t n_est, 
                                       ht_t *gt_ht, size_t topK, 
                                       size_t num_windows, double threshold) {
    if (!est_pairs || n_est == 0 || !gt_ht) {
        printf("No ground truth or estimates\n");
        return;
    }
    
    size_t persistence_threshold = (size_t)(threshold * num_windows);
    printf("\nPersistence threshold: %zu windows (%.1f%% of %zu)\n", 
           persistence_threshold, threshold * 100, num_windows);
    
    // Collect ground truth persistent items
    size_t actual_capacity = gt_ht->n_entries;
    persistent_pair_t *actual_pairs = malloc(sizeof(persistent_pair_t) * actual_capacity);
    size_t n_actual = ht_collect_pairs(gt_ht, actual_pairs, actual_capacity);
    qsort(actual_pairs, n_actual, sizeof(persistent_pair_t), pair_cmp_desc);
    
    // Count truly persistent items
    size_t n_true_persistent = 0;
    for (size_t i = 0; i < n_actual; i++) {
        if (actual_pairs[i].persistence >= persistence_threshold) {
            n_true_persistent++;
        } else {
            break;  // Sorted, so rest are also below threshold
        }
    }
    
    // Count estimated persistent items
    size_t n_est_persistent = 0;
    for (size_t i = 0; i < n_est; i++) {
        if (est_pairs[i].persistence >= persistence_threshold) {
            n_est_persistent++;
        }
    }
    
    printf("True persistent items: %zu\n", n_true_persistent);
    printf("Estimated persistent items: %zu\n", n_est_persistent);
    
    if (n_true_persistent == 0) {
        printf("No persistent items in ground truth!\n");
        free(actual_pairs);
        return;
    }
    
    // Calculate metrics using only persistent items
    size_t tp = 0;  // True positives
    double are_sum = 0.0;
    double aae_sum = 0.0;
    
    // Check estimated persistent items against ground truth
    for (size_t i = 0; i < n_est_persistent; i++) {
        uint32_t true_persistence = ht_get_persistence(gt_ht, est_pairs[i].key);
        
        if (true_persistence > persistence_threshold) {
            tp++;  // Correctly identified as persistent
            
            double diff = fabs((double)est_pairs[i].persistence - (double)true_persistence);
            double rel = (true_persistence == 0) ? (double)est_pairs[i].persistence : 
                        (diff / (double)true_persistence);
            are_sum += rel;
            aae_sum += diff;
        }
    }
    
    double precision = (n_est_persistent > 0) ? ((double)tp / (double)n_est_persistent) : 0.0;
    double recall = (n_true_persistent > 0) ? ((double)tp / (double)n_true_persistent) : 0.0;
    double F1 = (precision + recall > 0) ? (2 * precision * recall / (precision + recall)) : 0.0;
    double ARE = (tp > 0) ? (are_sum / (double)tp) : 0.0;
    double AAE = (tp > 0) ? (aae_sum / (double)tp) : 0.0;
    
    printf("\n=== Persistent Item Detection Metrics ===\n");
    printf("Precision: %.6f\n", precision);
    printf("Recall: %.6f\n", recall);
    printf("F1 Score: %.6f\n", F1);
    printf("ARE: %.6f\n", ARE);
    printf("AAE: %.6f\n", AAE);
    printf("True Positives: %zu\n", tp);
    
    free(actual_pairs);
}

static void print_throughput_stats(__u64 packets, double elapsed_seconds) {
    if (elapsed_seconds <= 1e-9) elapsed_seconds = 1e-9;
    double pps = (double)packets / elapsed_seconds;
    double mpps = pps / 1e6;
    printf("\n=== Throughput Statistics ===\n");
    printf("Total packets: %llu\n", packets);
    printf("Duration: %.2f seconds\n", elapsed_seconds);
    printf("Throughput: %.2f Mpps (%.2f Kpps)\n", mpps, pps / 1000.0);
}

static __u64 GenHashSeed(__u64 index) {
    __u64 x = index;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s -i <ifname> [-k topK] [-D duration] [-t trace_file] [-w windows] [-T threshold]\n"
            " -i <ifname>     network interface\n"
            " -k <topK>       top-K persistent items (default 50)\n"
            " -D <duration>   seconds to collect (default 10)\n"
            " -t <trace_file> .dat file for ground truth\n"
            " -w <windows>    number of windows (default 1600)\n"
            " -T <threshold>  persistence threshold 0-1 (default 0.5)\n",
            argv0);
}

int main(int argc, char **argv) {
    const char *ifname = NULL;
    const char *trace_file = NULL;
    int topK = 50;
    int collection_duration = 10;
    size_t num_windows = DEFAULT_NUM_WINDOWS;
    double persistence_threshold = DEFAULT_THRESHOLD;
    int opt;
    
    while ((opt = getopt(argc, argv, "i:k:D:t:w:T:")) != -1) {
        switch (opt) {
            case 'i': ifname = optarg; break;
            case 'k': topK = atoi(optarg); break;
            case 'D': collection_duration = atoi(optarg); break;
            case 't': trace_file = optarg; break;
            case 'w': num_windows = (size_t)atoi(optarg); break;
            case 'T': persistence_threshold = atof(optarg); break;
            default: usage(argv[0]); return 1;
        }
    }
    
    if (!ifname) {
        usage(argv[0]);
        return 1;
    }
    
    ht_t gt_ht = {0};
    size_t n_trace_items = 0;
    
    if (trace_file) {
        printf("Building window-based persistent ground truth from %s...\n", trace_file);
        n_trace_items = build_persistent_ground_truth(&gt_ht, trace_file, num_windows);
        if (n_trace_items > 0) {
            printf("Processed %zu items, %zu unique flows\n", n_trace_items, gt_ht.n_entries);
        }
    }
    
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface not found\n");
        ht_free(&gt_ht);
        return 1;
    }
    
    printf("\n=== Persistent Stable-Sketch eBPF ===\n\n");
    
    skel = persistent_stable_sketch_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load eBPF program\n");
        ht_free(&gt_ht);
        return 1;
    }
    
    sketch_fd = bpf_map__fd(skel->maps.persistent_sketch_map);
    
    struct PersistentStableSketch psk = {};
    psk.depth = MAX_DEPTH;
    psk.width = MAX_WIDTH;
    psk.lgn = 104;  
    psk.sum = 0;
    
    __u64 seed = 16319415375698566237ULL;
    for (int i = 0; i < MAX_DEPTH; i++) {
        psk.hash_seeds[i] = GenHashSeed((seed++));
        psk.scale_seeds[i] = GenHashSeed((seed++));  
        psk.hardner_seeds[i] = GenHashSeed((seed));
        seed++;
    }
    
    // Initialize all buckets
    for (int i = 0; i < MAX_DEPTH; i++) {
        for (int j = 0; j < MAX_WIDTH; j++) {
            psk.buckets[i][j].count = 0;
            psk.buckets[i][j].stablecount = 0;
            psk.buckets[i][j].last_arrived_packet_number = 0;
            memset(psk.buckets[i][j].key, 0, LGN);
        }
    }
    psk.packets_per_window = (__u64)(n_trace_items / num_windows);
    
    __u32 map_key = 0;
    if (bpf_map_update_elem(sketch_fd, &map_key, &psk, BPF_ANY) != 0) {
        perror("map update");
        ht_free(&gt_ht);
        persistent_stable_sketch_ebpf__destroy(skel);
        return 1;
    }
    
    struct bpf_program *prog = skel->progs.xdp_persistent_collect;
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        fprintf(stderr, "XDP attach failed\n");
        ht_free(&gt_ht);
        persistent_stable_sketch_ebpf__destroy(skel);
        return 1;
    }
    
    printf("XDP attached to %s\n", ifname);
    printf("Simulating %zu windows over %d seconds\n", num_windows, collection_duration);
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    double start_time = now_seconds();
    
    printf("Collecting packets...\n");

    for (int i = 0; i < collection_duration && !exiting; ++i) {
        sleep(1);
        if ((i + 1) % 5 == 0) {
            printf("  %d sec...\n", i + 1);
        }
    }
    
    printf("\n=== Reading sketch ===\n");
    
    if (bpf_map_lookup_elem(sketch_fd, &map_key, &psk) != 0) {
        fprintf(stderr, "Failed to read sketch\n");
        goto cleanup;
    }
    
    printf("Processed: %llu packets\n", psk.sum);
    printf("Sketch total packets and packets per window: %llu\n", psk.packets_per_window);

    persistent_pair_t *pairs = NULL;
    size_t n_pairs = 0;
    if (read_sketch_persistent_candidates(&psk, &pairs, &n_pairs) != 0) {
        fprintf(stderr, "Failed to read candidates\n");
        goto cleanup;
    }
    
    printf("Candidates: %zu\n", n_pairs);
    
    if (n_pairs > 0) {
        qsort(pairs, n_pairs, sizeof(persistent_pair_t), pair_cmp_desc);
        
        int k = topK;
        if ((size_t)k > n_pairs) k = (int)n_pairs;
        
        printf("\n=== Top-%d Persistent Items ===\n", k);
        for (int i = 0; i < k; ++i) {
            printf("%3d) persistence=%u | ", i + 1, pairs[i].persistence);
            print_flow_key(pairs[i].key);
            printf("\n");
        }
        
        if (trace_file && gt_ht.n_entries > 0) {
            compute_persistent_metrics(pairs, n_pairs, &gt_ht, (size_t)topK, 
                                       num_windows, persistence_threshold);
        }
    }
    
    if (psk.sum > 0) {
        double end_time = now_seconds();
        print_throughput_stats(psk.sum, end_time - start_time);
    }
    
    free(pairs);
    printf("\nDone.\n");
    
cleanup:
    if (link) bpf_link__destroy(link);
    persistent_stable_sketch_ebpf__destroy(skel);
    ht_free(&gt_ht);
    return 0;
}