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
#include "MultiHeavy_stable_sketch_common.h"
#include "MultiHeavy_stable_sketch_ebpf.skel.h"

#define KEY_SIZE 13
#define DEFAULT_NUM_WINDOWS 800
#define DEFAULT_THRESHOLD 0.5

static volatile sig_atomic_t exiting = 0;
static struct MultiHeavy_stable_sketch_ebpf *skel;
static int sketch_fd;

static void handle_signal(int sig) {
    exiting = 1;
}

typedef struct {
    uint8_t key[KEY_SIZE];
    uint32_t persistence;  
    uint32_t byte_counter;
    int first_inserted_seq_num;
    int last_inserted_seq_num;
    int burst_start_seq_num;
    int burst_end_seq_num;
    __u32 curr_burst_size;
    __u32 burst_gap_sum;
    int n_bursts;
    __u32 burst_rates_sum;
} MultiHeavy_pair_t;

typedef struct ht_entry {
    uint8_t key[KEY_SIZE];
    uint32_t persistence;
    uint32_t byte_counter;
    uint32_t first_inserted_seq_num;
    uint32_t last_inserted_seq_num;
    struct ht_entry *next;
    __u32 burst_start_seq_num;
    __u32 burst_end_seq_num;
    __u64 curr_burst_size;
    __u64 burst_gap_sum;
    int n_bursts;
    __u64 burst_rates_sum;
} ht_entry_t;

struct key13 {
    __u8 b[13];
};

struct burst_data {
    __u32 numerator;
    __u32 denominator;
    struct key13 key;
};

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

size_t ht_collect_pairs(ht_t *ht, MultiHeavy_pair_t *pairs, size_t capacity) {
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


size_t build_MultiHeavy_ground_truth(ht_t *ground_truth, const char *trace_file, 
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
    const MultiHeavy_pair_t *pa = a, *pb = b;
    if (pa->persistence < pb->persistence) return 1;
    if (pa->persistence > pb->persistence) return -1;
    return 0;
}

static int read_sketch_MultiHeavy_candidates(struct MultiHeavyStableSketch *psk, 
                                             MultiHeavy_pair_t **out_pairs, 
                                             size_t *out_n) {
    size_t max_candidates = MAX_DEPTH * MAX_WIDTH;
    MultiHeavy_pair_t *pairs = calloc(max_candidates, sizeof(MultiHeavy_pair_t));
    if (!pairs) return -1;
    
    size_t written = 0;
    for (int i = 0; i < psk->depth && i < MAX_DEPTH; i++) {
        for (int j = 0; j < psk->width && j < MAX_WIDTH; j++) {
            struct MultiHeavySBucket *b = &psk->buckets[i][j];
            if (b->count > 0) {
                memcpy(pairs[written].key, b->key, KEY_SIZE);
                pairs[written].persistence = b->count;
                pairs[written].byte_counter = b->byte_counter;
                pairs[written].first_inserted_seq_num = b-> first_inserted_packet_number;
                pairs[written].last_inserted_seq_num = b->last_arrived_packet_number;
                pairs[written].burst_rates_sum = b->burst_rates_sum;
                pairs[written].n_bursts = b->n_bursts;
                pairs[written].burst_gap_sum = b->burst_gap_sum;
                if (b->burst_calculated == 0){
                     __u32 denom = b->burst_end_seq_num - b->burst_start_seq_num; 
                    if (denom > 0){
                        pairs[written].burst_rates_sum += (int)b->curr_burst_size / denom;
                    }
                    pairs[written].n_bursts++;
                }
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
            " -k <topK>       top-K MultiHeavy items (default 50)\n"
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
        printf("Building window-based MultiHeavy ground truth from %s...\n", trace_file);
        n_trace_items = build_MultiHeavy_ground_truth(&gt_ht, trace_file, num_windows);
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
    
    printf("\n=== MultiHeavy Stable-Sketch eBPF ===\n\n");
    
    skel = MultiHeavy_stable_sketch_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load eBPF program\n");
        ht_free(&gt_ht);
        return 1;
    }
    
    sketch_fd = bpf_map__fd(skel->maps.MultiHeavy_sketch_map);
    
    struct MultiHeavyStableSketch psk = {};
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
    
    
    for (int i = 0; i < MAX_DEPTH; i++) {
        for (int j = 0; j < MAX_WIDTH; j++) {
            psk.buckets[i][j].count = 0;
            psk.buckets[i][j].stablecount = 0;
            psk.buckets[i][j].last_arrived_packet_number = 0;
            psk.buckets[i][j].byte_counter = 0;
            psk.buckets[i][j].replacement_bytes = 0;
            psk.buckets[i][j].first_inserted_packet_number = 0;
            memset(psk.buckets[i][j].key, 0, LGN);
        }
    }
    psk.packets_per_window = (__u64)(n_trace_items / num_windows);
    psk.burst_duration = 1000;
    
    __u32 map_key = 0;
    if (bpf_map_update_elem(sketch_fd, &map_key, &psk, BPF_ANY) != 0) {
        perror("map update");
        ht_free(&gt_ht);
        MultiHeavy_stable_sketch_ebpf__destroy(skel);
        return 1;
    }
    printf("11111111111111111");
    
    struct bpf_program *prog = skel->progs.xdp_MultiHeavy_collect;
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    printf("2222222222222222");
    if (!link) {
        fprintf(stderr, "XDP attach failed\n");
        ht_free(&gt_ht);
        MultiHeavy_stable_sketch_ebpf__destroy(skel);
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

    MultiHeavy_pair_t *pairs = NULL;
    size_t n_pairs = 0;
    if (read_sketch_MultiHeavy_candidates(&psk, &pairs, &n_pairs) != 0) {
        fprintf(stderr, "Failed to read candidates\n");
        goto cleanup;
    }
    
    printf("Candidates: %zu\n", n_pairs);
    
    
    if (n_pairs > 0) {
        qsort(pairs, n_pairs, sizeof(MultiHeavy_pair_t), pair_cmp_desc);
        for (int c = 0;c<n_pairs;c++){
            print_flow_key(pairs[c].key);
            int first_window = pairs[c].first_inserted_seq_num/1600;
            int last_window = pairs[c].last_inserted_seq_num/1600;
            int duration = last_window - first_window+1;
            uint32_t size =  pairs[c].byte_counter;
            double rate = size/duration;
            int n_bursts = pairs[c].n_bursts;
            double mean_burst = 0;
            double mean_burst_gap = 0;
            if (n_bursts > 1){
                mean_burst = pairs[c].burst_rates_sum / n_bursts;
                mean_burst_gap = pairs[c].burst_gap_sum/ (n_bursts-1);
            }
            
            
            printf("  duration =%u windows| ", duration);
            printf("  size=%u bytes| ", size);
            printf("  rate=%lf bytes-per-window| ", rate);
            printf("  burstiness=%lf | ", mean_burst * mean_burst_gap);
            printf("  counter=%u | ", pairs[c].persistence);
            if (pairs[c].byte_counter > 152000){
                printf("  elephant");
            }
            else{
                printf("  mice");
            }
            printf("\n");
        }
    }
    
    free(pairs);
    printf("\nDone.\n");
    
cleanup:
    if (link) bpf_link__destroy(link);
    MultiHeavy_stable_sketch_ebpf__destroy(skel);
    ht_free(&gt_ht);
    return 0;
}