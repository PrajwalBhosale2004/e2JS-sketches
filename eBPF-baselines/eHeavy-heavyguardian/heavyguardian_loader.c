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

#include "heavyguardian_parameters.h"

static int ifindex = -1;
static struct bpf_link *xdp_link = NULL;
static char pin_dir[256] = {0};
static volatile sig_atomic_t exiting = 0;

typedef struct xdp_stats
{
    __u64 rx_packets;
    __u64 rx_bytes;
} xdp_stats;


struct hg_node {
    uint8_t key[KEY_SIZE];
    uint32_t counter;
};


struct hg_bucket {
    struct hg_node cells[CELL_NUM];
};


typedef struct pair
{
    uint8_t key[KEY_SIZE];
    uint32_t count;
} pair_t;

static int pair_cmp_desc(const void *a, const void *b)
{
    const pair_t *pa = a, *pb = b;
    if (pa->count < pb->count)
        return 1;
    if (pa->count > pb->count)
        return -1;
    return 0;
}

typedef struct ht_entry
{
    uint8_t key[KEY_SIZE];
    uint32_t count;
    struct ht_entry *next;
} ht_entry_t;

typedef struct hash_table
{
    ht_entry_t **buckets;
    size_t n_buckets;
    size_t n_entries;
} ht_t;

static inline double now_seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0.0;
    }
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}


static inline uint32_t mix32_key(const uint8_t key[KEY_SIZE])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < KEY_SIZE; ++i)
    {
        uint32_t v = key[i];
        h ^= v;
        h *= 16777619u;
        h = (h << 13) | (h >> 19);
        h += 0x9e3779b9u;
    }
    return h;
}

static size_t next_pow2(size_t x)
{
    size_t p = 1;
    while (p < x)
        p <<= 1;
    return p;
}

int ht_init_with_hint(ht_t *ht, size_t expected_keys)
{
    if (!ht)
        return -1;
    size_t buckets = next_pow2((expected_keys > 0 ? (expected_keys * 2) : 1024));
    if (buckets < 1024)
        buckets = 1024;
    ht->n_buckets = buckets;
    ht->buckets = (ht_entry_t **)calloc(ht->n_buckets, sizeof(ht_entry_t *));
    if (!ht->buckets)
        return -1;
    ht->n_entries = 0;
    return 0;
}

void ht_free(ht_t *ht)
{
    if (!ht || !ht->buckets)
        return;
    for (size_t i = 0; i < ht->n_buckets; ++i)
    {
        ht_entry_t *e = ht->buckets[i];
        while (e)
        {
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

void ht_increment(ht_t *ht, const uint8_t key[KEY_SIZE])
{
    if (!ht || !ht->buckets)
        return;
    uint32_t h = mix32_key(key);
    size_t idx = (size_t)h & (ht->n_buckets - 1);
    ht_entry_t *e = ht->buckets[idx];
    while (e)
    {
        if (memcmp(e->key, key, KEY_SIZE) == 0)
        {
            e->count++;
            return;
        }
        e = e->next;
    }
    ht_entry_t *ne = (ht_entry_t *)malloc(sizeof(ht_entry_t));
    if (!ne)
        return;
    memcpy(ne->key, key, KEY_SIZE);
    ne->count = 1;
    ne->next = ht->buckets[idx];
    ht->buckets[idx] = ne;
    ht->n_entries++;
}

uint32_t ht_get_count(ht_t *ht, const uint8_t key[KEY_SIZE])
{
    if (!ht || !ht->buckets)
        return 0;
    uint32_t h = mix32_key(key);
    size_t idx = (size_t)h & (ht->n_buckets - 1);
    ht_entry_t *e = ht->buckets[idx];
    while (e)
    {
        if (memcmp(e->key, key, KEY_SIZE) == 0)
            return e->count;
        e = e->next;
    }
    return 0;
}

size_t ht_collect_pairs(ht_t *ht, pair_t *pairs, size_t capacity)
{
    if (!ht || !ht->buckets)
        return 0;
    size_t written = 0;
    for (size_t i = 0; i < ht->n_buckets && written < capacity; ++i)
    {
        ht_entry_t *e = ht->buckets[i];
        while (e && written < capacity)
        {
            memcpy(pairs[written].key, e->key, KEY_SIZE);
            pairs[written].count = e->count;
            written++;
            e = e->next;
        }
    }
    return written;
}


static int read_heavyguardian_candidates(int hg_fd, pair_t **out_pairs, size_t *out_n)
{
    
    ht_t merge_ht;
    if (ht_init_with_hint(&merge_ht, BUCKET_NUM * CELL_NUM) != 0)
    {
        fprintf(stderr, "Failed to init merge hash table\n");
        return -1;
    }

    
    for (uint32_t bucket_idx = 0; bucket_idx < BUCKET_NUM; bucket_idx++)
    {
        struct hg_bucket bucket;

        if (bpf_map_lookup_elem(hg_fd, &bucket_idx, &bucket) != 0)
            continue;

        
        for (int cell_idx = 0; cell_idx < CELL_NUM; cell_idx++)
        {
            if (bucket.cells[cell_idx].counter == 0)
                continue;

            
            int is_empty = 1;
            for (int i = 0; i < KEY_SIZE; i++)
            {
                if (bucket.cells[cell_idx].key[i] != 0)
                {
                    is_empty = 0;
                    break;
                }
            }
            if (is_empty)
                continue;

            
            uint32_t existing = ht_get_count(&merge_ht, bucket.cells[cell_idx].key);
            if (existing == 0)
            {
                ht_increment(&merge_ht, bucket.cells[cell_idx].key);
                
                uint32_t h = mix32_key(bucket.cells[cell_idx].key);
                size_t bidx = (size_t)h & (merge_ht.n_buckets - 1);
                ht_entry_t *e = merge_ht.buckets[bidx];
                while (e)
                {
                    if (memcmp(e->key, bucket.cells[cell_idx].key, KEY_SIZE) == 0)
                    {
                        e->count = bucket.cells[cell_idx].counter;
                        break;
                    }
                    e = e->next;
                }
            }
            else
            {
                
                if (bucket.cells[cell_idx].counter > existing)
                {
                    uint32_t h = mix32_key(bucket.cells[cell_idx].key);
                    size_t bidx = (size_t)h & (merge_ht.n_buckets - 1);
                    ht_entry_t *e = merge_ht.buckets[bidx];
                    while (e)
                    {
                        if (memcmp(e->key, bucket.cells[cell_idx].key, KEY_SIZE) == 0)
                        {
                            e->count = bucket.cells[cell_idx].counter;
                            break;
                        }
                        e = e->next;
                    }
                }
            }
        }
    }

    
    pair_t *pairs = calloc(merge_ht.n_entries, sizeof(pair_t));
    if (!pairs)
    {
        ht_free(&merge_ht);
        return -1;
    }

    size_t written = ht_collect_pairs(&merge_ht, pairs, merge_ht.n_entries);

    printf("Scanned %d buckets with %d cells each, collected %zu unique keys\n",
           BUCKET_NUM, CELL_NUM, written);

    ht_free(&merge_ht);

    *out_pairs = pairs;
    *out_n = written;
    return 0;
}


size_t build_ground_truth_from_trace(ht_t *ht, const char *trace_file)
{
    if (!ht || !trace_file)
        return 0;
    FILE *f = fopen(trace_file, "rb");
    if (!f)
    {
        fprintf(stderr, "build_ground_truth_from_trace: cannot open %s: %s\n",
                trace_file, strerror(errno));
        return 0;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return 0;
    }

    long fsz = ftell(f);
    if (fsz <= 0)
    {
        fclose(f);
        return 0;
    }
    rewind(f);
    size_t n_items = (size_t)(fsz / KEY_SIZE);
    if (n_items == 0)
    {
        fclose(f);
        return 0;
    }

    if (ht_init_with_hint(ht, n_items) != 0)
    {
        fprintf(stderr, "build_ground_truth_from_trace: ht init failed\n");
        fclose(f);
        return 0;
    }
    uint8_t buf[KEY_SIZE];
    size_t read = 0;
    for (size_t i = 0; i < n_items; ++i)
    {
        size_t r = fread(buf, 1, KEY_SIZE, f);
        if (r != KEY_SIZE)
            break;
        ht_increment(ht, buf);
        read++;
    }
    fclose(f);
    return read;
}


static void compute_and_print_metrics(pair_t *est_pairs, size_t n_est, 
                                      ht_t *gt_ht, size_t topK) {
    if (!est_pairs || n_est == 0 || !gt_ht) {
        printf("No ground truth available or no estimates\n");
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
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = 0; j < k; ++j) {
            if (memcmp(est_pairs[i].key, actual_pairs[j].key, KEY_SIZE) == 0) {
                correct++;
                break;
            }
        }
    }
    double precision = (k > 0) ? ((double)correct / (double)k) : 0.0;

    
    double are_sum = 0.0;
    double aae_sum = 0.0;
    
    for (size_t i = 0; i < k; ++i) {
        uint32_t est_count = est_pairs[i].count;
        
        
        uint32_t true_count = ht_get_count(gt_ht, est_pairs[i].key);
        
        if (true_count == 0) {
            
            aae_sum += est_count;
            are_sum += 1.0;
        } else {
            double diff = fabs((double)est_count - (double)true_count);
            double rel = diff / (double)true_count;
            are_sum += rel;
            aae_sum += diff;
        }
    }
    
    double ARE = (k > 0) ? (are_sum / (double)k) : 0.0;
    double AAE = (k > 0) ? (aae_sum / (double)k) : 0.0;

    printf("\nTop-%zu flow detection Metrics:\n", k);
    printf("  Precision: %.6f\n", precision);
    printf("  ARE of reported top-k flows: %.6f\n", ARE);
    printf("  AAE of reported top-k flows: %.6f\n", AAE);
    
    
    double memory_per_cell = KEY_SIZE + sizeof(uint32_t);
    double total_memory_bytes = BUCKET_NUM * CELL_NUM * memory_per_cell;
    double memory_kb = total_memory_bytes / 1024.0;
    printf("  Memory used: %.2f KB\n", memory_kb);

    free(actual_pairs);
}

static int read_xdp_stats(int stats_fd, __u64 *total_packets, __u64 *total_bytes)
{
    __u32 key = 0;
    xdp_stats values[128];

    memset(values, 0, sizeof(values));

    if (bpf_map_lookup_elem(stats_fd, &key, values) != 0)
    {
        fprintf(stderr, "Failed to read XDP stats: %s\n", strerror(errno));
        return -1;
    }

    *total_packets = 0;
    *total_bytes = 0;

    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus > 128)
        num_cpus = 128;

    for (int i = 0; i < num_cpus; i++)
    {
        *total_packets += values[i].rx_packets;
        *total_bytes += values[i].rx_bytes;
    }

    return 0;
}

static void print_throughput_stats(__u64 packets, __u64 bytes, double elapsed_seconds)
{
    const double ELAPSE_EPS = 1e-9;
    if (elapsed_seconds <= ELAPSE_EPS)
    {
        elapsed_seconds = ELAPSE_EPS;
    }

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

static void print_topk_table(pair_t *pairs, int k)
{
    printf("\n");
    printf("%-4s %-16s %-7s %-16s %-7s %-6s %-8s %-12s %-10s\n",
           "No", "Src IP", "S.Port", "Dst IP", "D.Port", "Proto", "Count", "Fingerprint", "L0FP");
    printf("==================================================================================================\n");

    for (int i = 0; i < k; ++i)
    {
        uint8_t *p = pairs[i].key;

        char src_ip[16], dst_ip[16];
        snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
        snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u", p[4], p[5], p[6], p[7]);

        uint16_t src_port = (p[8] << 8) | p[9];
        uint16_t dst_port = (p[10] << 8) | p[11];
        uint8_t proto = p[12];

        const char *proto_name = "???";
        if (proto == 6)
            proto_name = "TCP";
        else if (proto == 17)
            proto_name = "UDP";
        else if (proto == 1)
            proto_name = "ICMP";

        uint32_t fp = mix32_key(p);
        uint16_t fp16 = (uint16_t)(fp & 0xFFFF);
        uint64_t l0fp = ((uint64_t)fp << 32) | pairs[i].count;

        printf("%-4d %-16s %-7u %-16s %-7u %-6s %-8u %-12u %lu\n",
               i + 1, src_ip, src_port, dst_ip, dst_port,
               proto_name, pairs[i].count, fp16, l0fp);
    }
    printf("==================================================================================================\n");
}


static void int_exit(int sig)
{
    exiting = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -i <iface> -o <pin_dir> [-k topK] [-D duration] [-t trace_file] <bpf_obj>\n"
            " -i <iface>       network interface to attach XDP program\n"
            " -o <pin_dir>     bpffs pin directory (must exist) where maps will be pinned\n"
            " -k <topK>        top-K to print (default 50)\n"
            " -D <duration>    duration seconds for collection of data (default 10)\n"
            " -t <trace_file>  optional trace file for ground truth comparison\n"
            " <bpf_obj>        compiled BPF object (heavyguardian_xdp.o)\n",
            prog);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *map;
    const char *iface = NULL;
    const char *obj_file = NULL;
    const char *trace_file = NULL;
    int duration = 10;
    int topK = 50;
    int opt;

    while ((opt = getopt(argc, argv, "i:o:D:k:t:")) != -1)
    {
        switch (opt)
        {
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

    if (!iface || !pin_dir[0] || optind >= argc)
    {
        usage(argv[0]);
        return 1;
    }

    obj_file = argv[optind];

    ifindex = if_nametoindex(iface);
    if (!ifindex)
    {
        perror("if_nametoindex");
        return 1;
    }

    
    ht_t gt_ht = {0};
    size_t n_trace_items = 0;
    if (trace_file)
    {
        printf("Building ground-truth from %s....\n", trace_file);
        n_trace_items = build_ground_truth_from_trace(&gt_ht, trace_file);
        printf("Ground truth built: %zu items, %zu unique keys\n",
               n_trace_items, gt_ht.n_entries);
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    
    obj = bpf_object__open_file(obj_file, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: failed to open BPF object\n");
        ht_free(&gt_ht);
        return 1;
    }

    
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: failed to load BPF object\n");
        ht_free(&gt_ht);
        return 1;
    }

    
    prog = bpf_object__find_program_by_name(obj, "heavyguardian_xdp");
    if (!prog)
    {
        fprintf(stderr, "ERROR: XDP program 'heavyguardian_xdp' not found\n");
        ht_free(&gt_ht);
        return 1;
    }

    
    xdp_link = bpf_program__attach_xdp(prog, ifindex);
    if (!xdp_link)
    {
        fprintf(stderr, "ERROR: failed to attach XDP program\n");
        ht_free(&gt_ht);
        return 1;
    }

    printf("HeavyGuardian XDP attached on %s (ifindex %d)\n", iface, ifindex);
    printf("Configuration: %d buckets x %d cells = %d total cells\n", 
           BUCKET_NUM, CELL_NUM, BUCKET_NUM * CELL_NUM);
    
    
    double memory_per_cell = KEY_SIZE + sizeof(uint32_t); 
    double total_memory_bytes = BUCKET_NUM * CELL_NUM * memory_per_cell;
    double memory_kb = total_memory_bytes / 1024.0;
    printf("Memory used: %.2f KB (%.2f MB)\n", memory_kb, memory_kb / 1024.0);

    
    {
        struct stat st;
        if (stat(pin_dir, &st) != 0)
        {
            if (mkdir(pin_dir, 0755) != 0)
            {
                fprintf(stderr, "ERROR: cannot create pin dir %s: %s\n",
                        pin_dir, strerror(errno));
                goto cleanup;
            }
        }
    }

    
    bpf_object__for_each_map(map, obj)
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", pin_dir, bpf_map__name(map));
        if (bpf_map__pin(map, path) == 0)
        {
            printf("Pinned map: %s\n", path);
        }
    }

    
    char stats_pin[512];
    snprintf(stats_pin, sizeof(stats_pin), "%s/xdp_stats_map", pin_dir);

    int stats_fd = bpf_obj_get(stats_pin);
    if (stats_fd < 0)
    {
        fprintf(stderr, "Warning: Could not open stats map: %s\n", strerror(errno));
    }

    double start_time = now_seconds();
    printf("Collecting data for %d seconds. Press CTRL+C to stop early and print results.\n", duration);

    for (int i = 0; i < duration && !exiting; ++i)
    {
        sleep(1);
        if ((i + 1) % 5 == 0 && !exiting)
        {
            printf("Collecting... %d seconds elapsed\n", i + 1);
        }
    }

    if (!exiting)
    {
        printf("\n=== Collection complete, reading sketch ===\n");
    }
    else
    {
        printf("\n=== Collection interrupted, reading sketch ===\n");
    }

    
    __u64 total_packets = 0;
    __u64 total_bytes = 0;
    if (stats_fd >= 0)
    {
        if (read_xdp_stats(stats_fd, &total_packets, &total_bytes) == 0)
        {
            printf("XDP processed: %llu packets, %llu bytes\n", total_packets, total_bytes);
        }
        else
        {
            fprintf(stderr, "Warning: Could not read XDP stats\n");
        }
        close(stats_fd);
    }

    
    char hg_pin[512];
    snprintf(hg_pin, sizeof(hg_pin), "%s/heavyguardian_map", pin_dir);

    int hg_fd = bpf_obj_get(hg_pin);
    if (hg_fd < 0)
    {
        fprintf(stderr, "ERROR: bpf_obj_get failed for %s: %s\n", hg_pin, strerror(errno));
        goto cleanup;
    }

    printf("Opened pinned HeavyGuardian map: hg_fd = %d\n", hg_fd);

    pair_t *pairs = NULL;
    size_t n_pairs = 0;

    
    if (read_heavyguardian_candidates(hg_fd, &pairs, &n_pairs) != 0)
    {
        fprintf(stderr, "ERROR: read_heavyguardian_candidates failed\n");
        close(hg_fd);
        goto cleanup;
    }

    close(hg_fd);
    printf("HeavyGuardian recovered %zu flows\n", n_pairs);

    if (n_pairs > 0)
    {
        qsort(pairs, n_pairs, sizeof(pair_t), pair_cmp_desc);

        int k = topK;
        if ((size_t)k > n_pairs)
            k = (int)n_pairs;

        printf("\n=== Top-%d Heavy Hitters ===\n", k);
        print_topk_table(pairs, k);

        if (trace_file && gt_ht.n_entries > 0)
        {
            printf("\n=== Accuracy Metrics ===\n");
            compute_and_print_metrics(pairs, n_pairs, &gt_ht, (size_t)topK);
        }

        free(pairs);
    }
    else
    {
        printf("No heavy hitters found.\n");
    }

    if (total_packets > 0)
    {
        double end_time = now_seconds();
        double elapsed = end_time - start_time;
        print_throughput_stats(total_packets, total_bytes, elapsed);
    }

cleanup:
    printf("\nDetaching HeavyGuardian XDP...\n");
    if (xdp_link)
    {
        bpf_link__destroy(xdp_link);
        xdp_link = NULL;
    }
    if (obj)
    {
        bpf_object__close(obj);
    }
    ht_free(&gt_ht);

    printf("Done.\n");
    return 0;
}