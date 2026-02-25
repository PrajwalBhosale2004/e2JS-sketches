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
#include "stable_sketch_common.h"
#include "stable_sketch_ebpf.skel.h"

#define KEY_SIZE 13
#define GOLDEN_RATIO_64 0x9E3779B97F4A7C15ULL
#define AWARE_SEED 16319415375698566237ULL
#define SMALL_SEED 13091204281ULL

static volatile sig_atomic_t exiting = 0;
static struct stable_sketch_ebpf *skel;
static int sketch_fd;

static void handle_signal(int sig) {
    exiting = 1;
}

typedef struct {
    uint8_t key[KEY_SIZE];
    uint32_t count;
} pair_t;

typedef struct ht_entry {
    uint8_t key[KEY_SIZE];
    uint32_t count;
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

void ht_increment(ht_t *ht, const uint8_t key[KEY_SIZE]) {
    if (!ht || !ht->buckets) return;
    uint32_t h = mix32_key(key);
    size_t idx = (size_t)h & (ht->n_buckets - 1);
    ht_entry_t *e = ht->buckets[idx];
    while (e) {
        if (memcmp(e->key, key, KEY_SIZE) == 0) {
            e->count++;
            return;
        }
        e = e->next;
    }
    ht_entry_t *ne = (ht_entry_t*)malloc(sizeof(ht_entry_t));
    if (!ne) return;
    memcpy(ne->key, key, KEY_SIZE);
    ne->count = 1;
    ne->next = ht->buckets[idx];
    ht->buckets[idx] = ne;
    ht->n_entries++;
}

uint32_t ht_get_count(ht_t *ht, const uint8_t key[KEY_SIZE]) {
    if (!ht || !ht->buckets) return 0;
    uint32_t h = mix32_key(key);
    size_t idx = (size_t)h & (ht->n_buckets - 1);
    ht_entry_t *e = ht->buckets[idx];
    while (e) {
        if (memcmp(e->key, key, KEY_SIZE) == 0) return e->count;
        e = e->next;
    }
    return 0;
}

size_t ht_collect_pairs(ht_t *ht, pair_t *pairs, size_t capacity) {
    if (!ht || !ht->buckets) return 0;
    size_t written = 0;
    for (size_t i = 0; i < ht->n_buckets && written < capacity; ++i) {
        ht_entry_t *e = ht->buckets[i];
        while (e && written < capacity) {
            memcpy(pairs[written].key, e->key, KEY_SIZE);
            pairs[written].count = e->count;
            written++;
            e = e->next;
        }
    }
    return written;
}

size_t build_ground_truth_from_trace(ht_t *ht, const char *trace_file) {
    if (!ht || !trace_file) return 0;
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
    
    size_t n_items = (size_t)(fsz / KEY_SIZE);
    if (n_items == 0) {
        fclose(f);
        return 0;
    }
    
    if (ht_init_with_hint(ht, n_items) != 0) {
        fprintf(stderr, "ht init failed\n");
        fclose(f);
        return 0;
    }
    
    uint8_t buf[KEY_SIZE];
    size_t read = 0;
    
    for (size_t i = 0; i < n_items; ++i) {
        size_t r = fread(buf, 1, KEY_SIZE, f);
        if (r != KEY_SIZE) break;
        ht_increment(ht, buf);
        read++;
    }
    
    fclose(f);
    return read;
}

static int pair_cmp_desc(const void *a, const void *b) {
    const pair_t *pa = a, *pb = b;
    if (pa->count < pb->count) return 1;
    if (pa->count > pb->count) return -1;
    return 0;
}

static int read_sketch_candidates(struct StableSketch *sk, pair_t **out_pairs, size_t *out_n) {
    size_t max_candidates = MAX_DEPTH * MAX_WIDTH;
    pair_t *pairs = calloc(max_candidates, sizeof(pair_t));
    if (!pairs) return -1;
    
    size_t written = 0;
    for (int i = 0; i < sk->depth && i < MAX_DEPTH; i++) {
        for (int j = 0; j < sk->width && j < MAX_WIDTH; j++) {
            struct SBucket *b = &sk->buckets[i][j];
            if (b->count > 0) {
                memcpy(pairs[written].key, b->key, KEY_SIZE);
                pairs[written].count = b->count;
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

static void compute_and_print_metrics(pair_t *est_pairs, size_t n_est, ht_t *gt_ht, size_t topK) {
    if (!est_pairs || n_est == 0 || !gt_ht) {
        printf("No ground truth or estimates\n");
        return;
    }
    
    size_t actual_capacity = gt_ht->n_entries;
    pair_t *actual_pairs = malloc(sizeof(pair_t) * (actual_capacity > 0 ? actual_capacity : 1));
    size_t n_actual = ht_collect_pairs(gt_ht, actual_pairs, actual_capacity);
    qsort(actual_pairs, n_actual, sizeof(pair_t), pair_cmp_desc);
    
    size_t k = topK;
    if (k > n_actual) k = n_actual;
    if (k > n_est) k = n_est;
    
    size_t correct = 0;
    for (size_t i = 0; i < k; i++) {

        int found = 0;
        for (size_t j = 0; j < k; j++) {
            if (memcmp(est_pairs[i].key, actual_pairs[j].key, KEY_SIZE) == 0) {
                correct++;
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("[Not in Ground Truth] Est Key #%zu: ", i);
            print_flow_key(est_pairs[i].key);
            printf(" | est_count=%u\n", est_pairs[i].count);
        }
    }
    double precision = (k > 0) ? ((double)correct / (double)k) : 0.0;
    
    size_t tp = 0;
    for (size_t i = 0; i < k; i++) {

        int found = 0;
        for (size_t j = 0; j < n_est; j++) {
            if (memcmp(actual_pairs[i].key, est_pairs[j].key, KEY_SIZE) == 0) {
                tp++;
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("[Missed by Sketch] True Key #%zu: ", i);
            print_flow_key(actual_pairs[i].key);
            printf(" | true_count=%u\n", actual_pairs[i].count);
        }
    }
    double recall = (k > 0) ? ((double)tp / (double)k) : 0.0;
    
    double are_sum = 0.0;
    double aae_sum = 0.0;
    for (size_t i = 0; i < k; ++i) {
        uint32_t est_count = est_pairs[i].count;
        uint32_t true_count = ht_get_count(gt_ht, est_pairs[i].key);
        double diff = fabs((double)est_count - (double)true_count);
        double rel = (true_count == 0) ? (double)est_count : (diff / (double)true_count);
        are_sum += rel;
        aae_sum += diff;
    }
    
    double ARE = (k > 0) ? (are_sum / (double)k) : 0.0;
    double AAE = (k > 0) ? (aae_sum / (double)k) : 0.0;
    double F1 = (precision + recall > 0) ? (2 * precision * recall / (precision + recall)) : 0.0;
    
    printf("Top-%zu precision = %.6f, recall = %.6f, F1 = %.6f, ARE = %.6f, AAE = %.6f\n", 
           k, precision, recall, F1, ARE, AAE);
    
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
            "Usage: %s -i <ifname> [-k topK] [-D duration] [-t trace_file]\n"
            " -i <ifname>     network interface\n"
            " -k <topK>       top-K (default 50)\n"
            " -D <duration>   seconds (default 10)\n"
            " -t <trace_file> .dat file\n",
            argv0);
}

int main(int argc, char **argv) {
    const char *ifname = NULL;
    const char *trace_file = NULL;
    int topK = 50;
    int collection_duration = 8;
    int opt;
    
    while ((opt = getopt(argc, argv, "i:k:D:t:")) != -1) {
        switch (opt) {
            case 'i': ifname = optarg; break;
            case 'k': topK = atoi(optarg); break;
            case 'D': collection_duration = atoi(optarg); break;
            case 't': trace_file = optarg; break;
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
        printf("Building ground-truth from %s...\n", trace_file);
        n_trace_items = build_ground_truth_from_trace(&gt_ht, trace_file);
        printf("Ground truth: %zu items, %zu unique\n", n_trace_items, gt_ht.n_entries);
    }
    
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface not found\n");
        ht_free(&gt_ht);
        return 1;
    }
    
    printf("\n=== StableSketch eBPF ===\n\n");
    
    skel = stable_sketch_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load\n");
        ht_free(&gt_ht);
        return 1;
    }
    
    sketch_fd = bpf_map__fd(skel->maps.sketch_map);
    
    struct StableSketch sk = {};
    sk.depth = MAX_DEPTH;
    sk.width = MAX_WIDTH;
    sk.lgn = 104;  // 13 bytes * 8 bits
    sk.sum = 0;
    

    __u64 seed = 16319415375698566237ULL;

    for (int i = 0; i < MAX_DEPTH; i++) {
        sk.hash_seeds[i] = GenHashSeed((seed++));
        sk.scale_seeds[i] = GenHashSeed((seed++));  
        sk.hardner_seeds[i] = GenHashSeed((seed));
        seed++;
    }
    
    for (int i = 0; i < MAX_DEPTH; i++) {
        for (int j = 0; j < MAX_WIDTH; j++) {
            sk.buckets[i][j].count = 0;
            sk.buckets[i][j].stablecount = 0;
            memset(sk.buckets[i][j].key, 0, LGN);
        }
    }
    
    __u32 map_key = 0;
    if (bpf_map_update_elem(sketch_fd, &map_key, &sk, BPF_ANY) != 0) {
        perror("map update");
        ht_free(&gt_ht);
        stable_sketch_ebpf__destroy(skel);
        return 1;
    }
    
    struct bpf_program *prog = skel->progs.xdp_collect_5tuple;
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        fprintf(stderr, "attach failed\n");
        ht_free(&gt_ht);
        stable_sketch_ebpf__destroy(skel);
        return 1;
    }
    
    printf("XDP attached to %s\n", ifname);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    double start_time = now_seconds();
    __u64 prev_sum = 0;
    printf("Collecting for %d seconds...\n", collection_duration);
    
    for (int i = 0; i < collection_duration && !exiting; ++i) {
        sleep(1);
        if (bpf_map_lookup_elem(sketch_fd, &map_key, &sk) != 0) {
            fprintf(stderr, "Failed to read\n");
            goto cleanup;
        }
    
    printf("throughput : %llu pkt/s\n" , sk.sum-prev_sum);
    prev_sum = sk.sum;
    }
    
    printf("\n=== Reading sketch ===\n");
    
    if (bpf_map_lookup_elem(sketch_fd, &map_key, &sk) != 0) {
        fprintf(stderr, "Failed to read\n");
        goto cleanup;
    }
    
    printf("Processed: %llu packets\n", sk.sum);
    
    pair_t *pairs = NULL;
    size_t n_pairs = 0;
    if (read_sketch_candidates(&sk, &pairs, &n_pairs) != 0) {
        fprintf(stderr, "read failed\n");
        goto cleanup;
    }
    
    printf("Candidates: %zu\n", n_pairs);
    
    if (n_pairs > 0) {
        qsort(pairs, n_pairs, sizeof(pair_t), pair_cmp_desc);
        
        
        if (trace_file && gt_ht.n_entries > 0) {
            pair_t *gt_pairs = malloc(sizeof(pair_t) * gt_ht.n_entries);
            size_t n_gt = ht_collect_pairs(&gt_ht, gt_pairs, gt_ht.n_entries);
            qsort(gt_pairs, n_gt, sizeof(pair_t), pair_cmp_desc);

            free(gt_pairs);
        }
        
        int k = topK;
        if ((size_t)k > n_pairs) k = (int)n_pairs;
        
        printf("\n=== Top-%d Heavy Hitters ===\n", k);
        for (int i = 0; i < k; ++i) {
            printf("%3d) cnt=%u | ", i + 1, pairs[i].count);
            print_flow_key(pairs[i].key);
            printf("\n");
        }
        
        if (trace_file) {
            printf("\n=== Accuracy Metrics ===\n");
            compute_and_print_metrics(pairs, n_pairs, &gt_ht, (size_t)topK);
        }
    }
    
    if (sk.sum > 0) {
        double end_time = now_seconds();
        print_throughput_stats(sk.sum, end_time - start_time);
    }
    
    free(pairs);
    printf("\nDone.\n");
    
cleanup:
    if (link) bpf_link__destroy(link);
    stable_sketch_ebpf__destroy(skel);
    ht_free(&gt_ht);
    return 0;
}