// StableSketch_main.c - Benchmark version similar to BubbleSketch_main.c
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
#include "StableSketch.h"
#include "datatypes.h"
#include "hash.h"
#include "util.h"

#define MAX_INSERT 45996697 // Maximum number of packets to process
#define KEY_LEN 13          // Length of each key in the dataset

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

// Hash map functions
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
    int MEM = 300;  // Memory in KB
    int K = 1000;   // Top-K parameter
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
    
    // Initialize StableSketch
    printf("Initializing StableSketch\n");
    int row = MEM * 1024 / (16 * 4);  // Calculate row count based on memory
    int depth = 4;  // Standard depth
    StableSketch* sketch = StableSketch_create(depth, row, 8 * KEY_LEN);
    if (!sketch) {
        printf("Failed to initialize StableSketch\n");
        return -1;
    }
    printf("StableSketch initialized with depth=%d, width=%d\n\n", depth, row);
    
    // Setup dataset file reading
    char default_dataset[40] = "./10.dat";
    if (dataset[0] == '\0') {
        strcpy(dataset, default_dataset);
    }
    printf("Dataset: %s\n\n", dataset);
    
    FILE* fin = fopen(dataset, "rb");
    if (!fin) {
        printf("Dataset not exists!\n");
        StableSketch_destroy(sketch);
        return -1;
    }
    
    // Data structures for ground truth
    HashMap* ground_truth = HashMap_create();
    HashMap* top_k_truth = HashMap_create();
    char** strings = (char**)malloc(MAX_INSERT * sizeof(char*));
    char tmp[KEY_LEN];
    
    // Read dataset and build ground truth
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
    
    // Measure insertion throughput
    printf("*************Throughput (insert)************\n");
    struct timespec time1, time2;
    long long resns;
    
    clock_gettime(CLOCK_MONOTONIC, &time1);
    for (int i = 0; i < packet_num; i++) {
        StableSketch_Update(sketch, (unsigned char*)strings[i], 1);
    }
    clock_gettime(CLOCK_MONOTONIC, &time2);
    
    resns = (long long)(time2.tv_sec - time1.tv_sec) * 1000000000LL + 
            (time2.tv_nsec - time1.tv_nsec);
    double throughput = (double)1000.0 * packet_num / resns;
    printf("Throughput of StableSketch (insert): %.6lf Mips\n\n", throughput);
    
    // Process results
    printf("*************Processing Results************\n");
    
    // Build sorted ground truth for top-K
    printf("Preparing true flow rankings...\n");
    FlowPair* all_flows;
    int flow_count = HashMap_to_array(ground_truth, &all_flows);
    qsort(all_flows, flow_count, sizeof(FlowPair), flow_compare);
    
    // Store top K+10 flows for comparison
    int comparison_size = (K + 10 < flow_count) ? K + 10 : flow_count;
    for (int i = 0; i < comparison_size; i++) {
        HashMap_put(top_k_truth, all_flows[i].key, all_flows[i].frequency);
    }
    
    printf("Ground truth prepared (top %d flows)\n\n", comparison_size);
    
    // Query StableSketch for heavy hitters
    val_tp total_count = StableSketch_GetCount(sketch);
    val_tp threshold = (val_tp)(total_count * 0.001);  // 0.1% threshold for top-K
    
    myvector results;
    myvector_init(&results);
    StableSketch_Query(sketch, threshold, &results);
    
    printf("StableSketch returned %zu results above threshold\n\n", results.size);
    
    // Calculate metrics (PRE, ARE, AAE)
    printf("*************Calculating Metrics************\n");
    int accepted = 0;
    double total_aae = 0.0;
    double total_are = 0.0;
    
    // Check top K from ground truth
    for (int i = 0; i < K && i < flow_count; i++) {
        key_tp search_key;
        memset(&search_key, 0, sizeof(search_key));
        memcpy(search_key.key, all_flows[i].key, KEY_LEN);
        
        val_tp estimated = StableSketch_PointQuery(sketch, search_key.key);
        int actual_freq = all_flows[i].frequency;
        
        if (estimated > 0) {
            accepted++;
            int absolute_error = abs((int)estimated - actual_freq);
            double relative_error = (double)absolute_error / actual_freq;
            
            total_aae += absolute_error;
            total_are += relative_error;
        }
    }
    
    printf("\n*************Final Results************\n");
    printf("StableSketch:\n");
    printf("\tAccepted: %d/%d (%.10f)\n", accepted, K, (double)accepted / K);
    printf("\tARE: %.10f\n", total_are / K);
    printf("\tAAE: %.10f\n", total_aae / K);
    printf("\tTotal Count: %lu\n", total_count);
    printf("\tThreshold: %lu\n", threshold);
    printf("\tResults Found: %zu\n", results.size);
    
    // Cleanup
    printf("\nCleaning up...\n");
    for (int i = 0; i < packet_num; i++) {
        free(strings[i]);
    }
    free(strings);
    free(all_flows);
    HashMap_destroy(ground_truth);
    HashMap_destroy(top_k_truth);
    myvector_free(&results);
    StableSketch_destroy(sketch);
    
    printf("Done!\n");
    return 0;
}