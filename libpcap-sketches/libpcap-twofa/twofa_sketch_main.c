#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include "twofa_sketch.c"

#define MAX_INSERT 45996697
#define KEY_LEN 13

#define HASH_MAP_SIZE 1000000

typedef struct HashEntry {
    char key[KEY_LEN + 1];
    int value;
    struct HashEntry* next;
} HashEntry;

typedef struct HashMap {
    HashEntry* buckets[HASH_MAP_SIZE];
    int size;
} HashMap;

unsigned int hash_string(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % HASH_MAP_SIZE;
}

HashMap* HashMap_create() {
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    memset(map->buckets, 0, sizeof(map->buckets));
    map->size = 0;
    return map;
}

void HashMap_put(HashMap* map, const char* key, int value) {
    unsigned int index = hash_string(key);
    HashEntry* entry = map->buckets[index];
    
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            entry->value = value;
            return;
        }
        entry = entry->next;
    }
    
    entry = (HashEntry*)malloc(sizeof(HashEntry));
    strcpy(entry->key, key);
    entry->value = value;
    entry->next = map->buckets[index];
    map->buckets[index] = entry;
    map->size++;
}

int HashMap_get(HashMap* map, const char* key) {
    unsigned int index = hash_string(key);
    HashEntry* entry = map->buckets[index];
    
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return 0;
}

void HashMap_increment(HashMap* map, const char* key) {
    HashMap_put(map, key, HashMap_get(map, key) + 1);
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

typedef struct FlowPair {
    char key[KEY_LEN + 1];
    int frequency;
} FlowPair;

int flow_compare(const void* a, const void* b) {
    const FlowPair* fa = (const FlowPair*)a;
    const FlowPair* fb = (const FlowPair*)b;
    return fb->frequency - fa->frequency;
}

int HashMap_to_array(HashMap* map, FlowPair** flows) {
    *flows = (FlowPair*)malloc(map->size * sizeof(FlowPair));
    int count = 0;
    
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        HashEntry* entry = map->buckets[i];
        while (entry) {
            strcpy((*flows)[count].key, entry->key);
            (*flows)[count].frequency = entry->value;
            count++;
            entry = entry->next;
        }
    }
    return count;
}

int main(int argc, char** argv) {
    int MEM = 100;
    int K = 1000;
    int c;
    char dataset[40] = {'\0'};
    
    while ((c = getopt(argc, argv, "d:m:k:")) != -1) {
        switch (c) {
            case 'd':
                strcpy(dataset, optarg);
                break;
            case 'm':
                MEM = atoi(optarg);
                break;
            case 'k':
                K = atoi(optarg);
                break;
            default:
                printf("Usage: %s [-d dataset] [-m memory_kb] [-k top_k]\n", argv[0]);
                return -1;
        }
    }
    
    printf("MEM=%dKB\n", MEM);
    printf("Find top %d\n\n", K);
    
    printf("Initializing 2FASketch\n");
    int threshold = 100;  // Threshold for heavy part
    uint32_t bucket_num = (MEM * 1024) / (COUNTER_PER_BUCKET * sizeof(Counter));
    if (bucket_num > MAX_BUCKETS) bucket_num = MAX_BUCKETS;
    if (bucket_num == 0) bucket_num = 1;
    
    Elastic_2FASketch* sketch = sketch_create(bucket_num, threshold);
    if (!sketch) {
        printf("Failed to create 2FASketch!\n");
        return -1;
    }
    printf("2FASketch initialized with %d buckets in heavy part\n\n", 
           sketch->hp.bucket_num);
    
    char default_dataset[40] = "../dats/10.dat";
    if (dataset[0] == '\0') {
        strcpy(dataset, default_dataset);
    }
    printf("Dataset: %s\n\n", dataset);
    
    FILE* fin = fopen(dataset, "rb");
    if (!fin) {
        printf("Dataset not exists!\n");
        return -1;
    }
    
    HashMap* ground_truth = HashMap_create();
    HashMap* top_k_truth = HashMap_create();
    char** strings = (char**)malloc(MAX_INSERT * sizeof(char*));
    char tmp[KEY_LEN];
    
    printf("Reading dataset and building ground truth...\n");
    int packet_num = 0;
    for (int i = 0; i < MAX_INSERT; i++) {
        if (feof(fin)) {
            break;
        }
        
        size_t bytes_read = fread(tmp, 1, KEY_LEN, fin);
        if (bytes_read != KEY_LEN) {
            break;
        }
        
        strings[i] = (char*)malloc(KEY_LEN * sizeof(char));
        memcpy(strings[i], tmp, KEY_LEN);
        
        HashMap_increment(ground_truth, strings[i]);
        packet_num++;
    }
    fclose(fin);
    
    printf("Total packets processed: %d\n\n", packet_num);
    
    struct timespec time1, time2;
    long long resns;
    
    clock_gettime(CLOCK_MONOTONIC, &time1);
    for (int i = 0; i < packet_num; i++) {
        sketch_insert(sketch, (const uint8_t*)strings[i], 1);
    }
    clock_gettime(CLOCK_MONOTONIC, &time2);
    
    resns = (long long)(time2.tv_sec - time1.tv_sec) * 1000000000LL + 
            (time2.tv_nsec - time1.tv_nsec);
    double throughput = (double)1000.0 * packet_num / resns;
    printf("Throughput of 2FASketch (insert): %.6lf Mips\n\n", throughput);
    
    printf("Preparing true flow rankings...\n");
    FlowPair* all_flows;
    int flow_count = HashMap_to_array(ground_truth, &all_flows);
    qsort(all_flows, flow_count, sizeof(FlowPair), flow_compare);
    
    int comparison_size = (K + 10 < flow_count) ? K + 10 : flow_count;
    for (int i = 0; i < comparison_size; i++) {
        HashMap_put(top_k_truth, all_flows[i].key, all_flows[i].frequency);
    }
    
    printf("Ground truth prepared (top %d flows)\n\n", comparison_size);
    
    int accepted = 0;
    double total_aae = 0.0;
    double total_are = 0.0;
    
    int max_possible = sketch->hp.bucket_num * MAX_VALID_COUNTER;
    int alloc_size = (max_possible > K * 10) ? K * 10 : max_possible; 
    
    uint32_t* out_keys = (uint32_t*)malloc(alloc_size * sizeof(uint32_t));
    uint32_t* out_vals = (uint32_t*)malloc(alloc_size * sizeof(uint32_t));
    FlowPair* sketch_results = (FlowPair*)malloc(alloc_size * sizeof(FlowPair));
    
    if (!out_keys || !out_vals || !sketch_results) {
        printf("Memory allocation failed!\n");
        return -1;
    }
    
    int out_num = alloc_size;
    heavypart_get_heavy_hitters(&sketch->hp, 1, out_keys, out_vals, &out_num);
    int result_count = out_num;
    
    if (result_count > alloc_size) {
        printf("Warning: More results than allocated, limiting to %d\n", alloc_size);
        result_count = alloc_size;
    }
    
    printf("Found %d heavy hitters in sketch\n", result_count);
    
    for (int i = 0; i < result_count; i++) {
        snprintf(sketch_results[i].key, KEY_LEN + 1, "fp_%08x", out_keys[i]);
        sketch_results[i].frequency = out_vals[i];
    }
    
    free(out_keys);
    free(out_vals);
    
    if (result_count > 0) {
        qsort(sketch_results, result_count, sizeof(FlowPair), flow_compare);
    }
    
    printf("\nNote: 2FASketch stores fingerprints, not full keys.\n");
    printf("Comparing frequencies only (key matching unavailable).\n\n");
    
    for (int i = 0; i < result_count && i < K; i++) {
        int predicted_freq = sketch_results[i].frequency;
        int actual_freq = (i < comparison_size) ? all_flows[i].frequency : 0;
        
        if (actual_freq > 0) {
            int best_match = 0;
            for (int j = 0; j < comparison_size; j++) {
                if (abs(all_flows[j].frequency - predicted_freq) < best_match || best_match == 0) {
                    best_match = abs(all_flows[j].frequency - predicted_freq);
                    actual_freq = all_flows[j].frequency;
                }
            }
            
            if (best_match < actual_freq * 0.5) {
                accepted++;
                int absolute_error = abs(actual_freq - predicted_freq);
                double relative_error = (double)absolute_error / actual_freq;
                
                total_aae += absolute_error;
                total_are += relative_error;
            }
        }
    }
    
    printf("\n*************Final Results************\n");
    printf("2FASketch:\n");
    printf("\tFlows detected: %d\n", result_count);
    printf("\tAccepted (approx): %d/%d (%.10f)\n", accepted, K, (double)accepted / K);
    printf("\tARE (approx): %.10f\n", total_are / K);
    printf("\tAAE (approx): %.10f\n", total_aae / K);
    printf("\tHeavy part evictions: %d\n", sketch->hp.cnt_all);
    
    printf("\n** Note: Accuracy metrics are approximate due to fingerprint-only storage **\n");
    
    printf("\nCleaning up...\n");
    for (int i = 0; i < packet_num; i++) {
        free(strings[i]);
    }
    free(strings);
    free(all_flows);
    free(sketch_results);
    HashMap_destroy(ground_truth);
    HashMap_destroy(top_k_truth);
    sketch_destroy(sketch);
    
    printf("Done!\n");
    return 0;
}