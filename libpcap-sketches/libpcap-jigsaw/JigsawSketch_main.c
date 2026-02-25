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
#include "JigsawSketch.c"

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
    int K = 1000;   
    int c;
    char dataset[40] = {'\0'};
    
    
    while ((c = getopt(argc, argv, "d:k:")) != -1) {
        switch (c) {
            case 'd':
                strcpy(dataset, optarg);
                break;
            case 'k':
                K = atoi(optarg);
                break;
            default:
                printf("Usage: %s [-d dataset] [-k top_k]\n", argv[0]);
                return -1;
        }
    }
    
    printf("Find top %d\n\n", K);
    
    
    printf("Initializing JigsawSketch\n");
    sketch_t sketch;
    if (sketch_init(&sketch) != 0) {
        fprintf(stderr, "Failed to initialize JigsawSketch\n");
        return -1;
    }
    
    
    srand(time(NULL));
    
    printf("JigsawSketch initialized with %d buckets\n", BUCKET_NUM);
    printf("Heavy cells per bucket: %d\n", CELL_NUM_H);
    printf("Light cells per bucket: %d\n", CELL_NUM_L);
    printf("Left part bits: %d\n\n", LEFT_PART_BITS);
    
    
    char default_dataset[40] = "./10.dat";
    if (dataset[0] == '\0') {
        strcpy(dataset, default_dataset);
    }
    printf("Dataset: %s\n\n", dataset);
    
    FILE* fin = fopen(dataset, "rb");
    if (!fin) {
        printf("Dataset not exists!\n");
        sketch_free(&sketch);
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
    
    
    printf("*************Throughput (insert)************\n");
    struct timespec time1, time2;
    long long resns;
    
    clock_gettime(CLOCK_MONOTONIC, &time1);
    for (int i = 0; i < packet_num; i++) {
        sketch_insert(&sketch, (uint8_t*)strings[i]);
    }
    clock_gettime(CLOCK_MONOTONIC, &time2);
    
    resns = (long long)(time2.tv_sec - time1.tv_sec) * 1000000000LL + 
            (time2.tv_nsec - time1.tv_nsec);
    double throughput = (double)1000.0 * packet_num / resns;
    printf("Throughput of JigsawSketch (insert): %.6lf Mips\n\n", throughput);
    
    
    printf("*************Processing Results************\n");
    
    
    size_t max_candidates = BUCKET_NUM * CELL_NUM_H;
    uint8_t **est_keys = (uint8_t**)malloc(sizeof(uint8_t*) * max_candidates);
    uint32_t *est_counts = (uint32_t*)malloc(sizeof(uint32_t) * max_candidates);
    
    for (size_t i = 0; i < max_candidates; ++i) {
        est_keys[i] = (uint8_t*)malloc(KEY_SIZE);
    }
    
    size_t n_est = sketch_get_estimates(&sketch, est_keys, est_counts, max_candidates);
    printf("Recovered %zu flows from sketch\n", n_est);
    
    
    FlowPair* estimated_flows = (FlowPair*)malloc(n_est * sizeof(FlowPair));
    for (size_t i = 0; i < n_est; i++) {
        memcpy(estimated_flows[i].key, est_keys[i], KEY_LEN);
        estimated_flows[i].frequency = est_counts[i];
    }
    
    
    qsort(estimated_flows, n_est, sizeof(FlowPair), flow_compare);
    
    
    printf("Preparing true flow rankings...\n");
    FlowPair* all_flows;
    int flow_count = HashMap_to_array(ground_truth, &all_flows);
    qsort(all_flows, flow_count, sizeof(FlowPair), flow_compare);
    
    
    int comparison_size = (K + 10 < flow_count) ? K + 10 : flow_count;
    for (int i = 0; i < comparison_size; i++) {
        HashMap_put(top_k_truth, all_flows[i].key, all_flows[i].frequency);
    }
    
    printf("Ground truth prepared (top %d flows)\n\n", comparison_size);
    
    
    printf("*************Calculating Metrics************\n");
    int accepted = 0;
    double total_aae = 0.0;
    double total_are = 0.0;
    
    
    size_t eval_count = (K < n_est) ? K : n_est;
    
    for (size_t i = 0; i < eval_count; i++) {
        char* result_str = estimated_flows[i].key;
        int result_val = estimated_flows[i].frequency;
        
        if (result_val == 0 || result_str[0] == '\0') {
            continue;
        }
        
        int actual_freq = HashMap_get(top_k_truth, result_str);
        
        if (actual_freq > 0) {
            accepted++;
            int absolute_error = abs(actual_freq - result_val);
            double relative_error = (double)absolute_error / actual_freq;
            
            total_aae += absolute_error;
            total_are += relative_error;
        }
    }
    
    printf("\n*************Final Results************\n");
    printf("JigsawSketch:\n");
    printf("\tAccepted: %d/%d (%.10f)\n", accepted, K, (double)accepted / K);
    printf("\tARE: %.10f\n", total_are / K);
    printf("\tAAE: %.10f\n", total_aae / K);
    if (n_est > 0) {
        printf("\tMax Frequency (estimated): %d\n", estimated_flows[0].frequency);
    }
    printf("\tTrue Max Frequency: %d\n", all_flows[0].frequency);
    
    
    printf("\nCleaning up...\n");
    for (int i = 0; i < packet_num; i++) {
        free(strings[i]);
    }
    free(strings);
    free(all_flows);
    free(estimated_flows);
    
    for (size_t i = 0; i < max_candidates; ++i) {
        free(est_keys[i]);
    }
    free(est_keys);
    free(est_counts);
    
    HashMap_destroy(ground_truth);
    HashMap_destroy(top_k_truth);
    sketch_free(&sketch);
    
    printf("Done!\n");
    return 0;
}
