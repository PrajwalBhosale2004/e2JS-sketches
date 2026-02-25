#ifndef __TWOFA_SKETCH_C__
#define __TWOFA_SKETCH_C__

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUCKETS 1024
#define COUNTER_PER_BUCKET 8
#define MAX_VALID_COUNTER 7
#define KEY_LEN 13

#define CONSTANT_NUMBER 2654435761u
#define ANOTHER_BIG_PRIME_NUMBER 3344921057u

#define UPDATE_GUARD_VAL(guard_val) ((guard_val) + 1)
#define JUDGE_IF_SWAP(min_val, guard_val) ((guard_val) > (min_val))

typedef struct {
    uint32_t fp;
    uint32_t value;
} Counter;

typedef struct {
    Counter slots[COUNTER_PER_BUCKET];
} Bucket;

typedef struct {
    Bucket* buckets;
    uint32_t bucket_num;
    uint32_t cnt;
    uint32_t cnt_all;
} Elastic_2FASketch_Heavypart;

typedef struct {
    Elastic_2FASketch_Heavypart hp;
    uint32_t thres_set;
} Elastic_2FASketch;

static inline uint32_t key_to_fp(const uint8_t* key, size_t key_len) {
    if (key_len >= 4) {
        return ((uint32_t)key[0] << 24) |
               ((uint32_t)key[1] << 16) |
               ((uint32_t)key[2] << 8) |
               ((uint32_t)key[3]);
    }
    return 0;
}

static inline uint32_t CalculateBucketPos(uint32_t fp) {
    return ((fp * CONSTANT_NUMBER) >> 15);
}

static inline uint32_t CalculateBucketPos2(uint32_t fp) {
    return ((fp * ANOTHER_BIG_PRIME_NUMBER) >> 12);
}

static inline uint32_t bucket_get_guard(Bucket* b) {
    return b->slots[MAX_VALID_COUNTER].value;
}

static inline void bucket_set_guard(Bucket* b, uint32_t guard_val) {
    b->slots[MAX_VALID_COUNTER].value = guard_val;
}

static inline void counter_init(Counter* c) {
    c->fp = 0;
    c->value = 0;
}

static inline void counter_set(Counter* c, uint32_t fp, uint32_t val) {
    c->fp = fp;
    c->value = val;
}

static inline void counter_inc(Counter* c, uint32_t f) {
    if (c->value < 0xFFFFFFFF - f) {
        c->value += f;
    } else {
        c->value = 0xFFFFFFFF;
    }
}

static inline void bucket_init(Bucket* b) {
    for (int i = 0; i < COUNTER_PER_BUCKET; i++) {
        counter_init(&b->slots[i]);
    }
}

Elastic_2FASketch_Heavypart* heavypart_create(uint32_t bucket_num) {
    Elastic_2FASketch_Heavypart* hp = malloc(sizeof(Elastic_2FASketch_Heavypart));
    if (!hp) return NULL;
    
    hp->buckets = calloc(bucket_num, sizeof(Bucket));
    if (!hp->buckets) {
        free(hp);
        return NULL;
    }
    
    hp->bucket_num = bucket_num;
    hp->cnt = 0;
    hp->cnt_all = 0;
    
    return hp;
}

void heavypart_destroy(Elastic_2FASketch_Heavypart* hp) {
    if (!hp) return;
    free(hp->buckets);
    free(hp);
}

void heavypart_clear(Elastic_2FASketch_Heavypart* hp) {
    if (!hp) return;
    hp->cnt = 0;
    hp->cnt_all = 0;
    for (uint32_t i = 0; i < hp->bucket_num; i++) {
        bucket_init(&hp->buckets[i]);
    }
}

int heavypart_quick_insert(Elastic_2FASketch_Heavypart* hp, 
                           const uint8_t* key, 
                           uint32_t f, 
                           uint32_t thres_set) {
    if (!hp || !key) return -1;
    
    uint32_t fp = key_to_fp(key, KEY_LEN);
    
    uint32_t pos;
    if (thres_set == 0) {
        pos = CalculateBucketPos2(fp) % hp->bucket_num;
    } else {
        pos = CalculateBucketPos(fp) % hp->bucket_num;
    }
    
    if (pos >= hp->bucket_num) return -1;
    
    Bucket* bucket = &hp->buckets[pos];
    
    int min_idx = 0;
    uint32_t min_val = 0xFFFFFFFF;
    int empty_idx = -1;
    
    for (int i = 0; i < MAX_VALID_COUNTER; i++) {
        Counter* c = &bucket->slots[i];
        
        if (c->fp == fp) {
            counter_inc(c, f);
            return 0;
        }
        
        if (c->value == 0 && empty_idx == -1) {
            empty_idx = i;
        }
        
        if (c->value < min_val) {
            min_val = c->value;
            min_idx = i;
        }
    }
    
    if (empty_idx >= 0) {
        counter_set(&bucket->slots[empty_idx], fp, f);
        return 0;
    }
    
    if (thres_set > 0 && min_val >= thres_set) {
        hp->cnt++;
        return thres_set;
    }
    
    hp->cnt_all++;
    uint32_t guard_val = bucket_get_guard(bucket);
    guard_val = UPDATE_GUARD_VAL(guard_val);
    
    if (!JUDGE_IF_SWAP(min_val, guard_val)) {
        bucket_set_guard(bucket, guard_val);
        return 2;
    }
    
    bucket_set_guard(bucket, 0);
    counter_set(&bucket->slots[min_idx], fp, guard_val);
    
    return 1;
}

uint32_t heavypart_query(const Elastic_2FASketch_Heavypart* hp,
                        const uint8_t* key,
                        uint32_t thres_set) {
    if (!hp || !key) return 0;
    
    uint32_t fp = key_to_fp(key, KEY_LEN);
    uint32_t pos = CalculateBucketPos(fp) % hp->bucket_num;
    
    if (pos >= hp->bucket_num) return 0;
    
    const Bucket* bucket = &hp->buckets[pos];
    uint32_t result = 0;
    uint32_t min_val = 0xFFFFFFFF;
    
    for (int i = 0; i < MAX_VALID_COUNTER; i++) {
        if (bucket->slots[i].fp == fp) {
            result += bucket->slots[i].value;
        }
        if (bucket->slots[i].value < min_val) {
            min_val = bucket->slots[i].value;
        }
    }
    
    if (min_val >= thres_set) {
        pos = CalculateBucketPos2(fp) % hp->bucket_num;
        if (pos < hp->bucket_num) {
            bucket = &hp->buckets[pos];
            for (int i = 0; i < MAX_VALID_COUNTER; i++) {
                if (bucket->slots[i].fp == fp) {
                    result += bucket->slots[i].value;
                }
            }
        }
    }
    
    return result;
}

void heavypart_get_heavy_hitters(Elastic_2FASketch_Heavypart* hp,
                                 uint32_t threshold,
                                 uint32_t* out_keys,
                                 uint32_t* out_vals,
                                 int* out_num) {
    if (!hp || !out_num) return;
    
    int count = 0;
    int max = *out_num;
    
    for (uint32_t b = 0; b < hp->bucket_num; b++) {
        Bucket* bucket = &hp->buckets[b];
        for (int i = 0; i < MAX_VALID_COUNTER; i++) {
            Counter* c = &bucket->slots[i];
            if (c->value >= threshold && c->fp != 0) {
                if (count < max && out_keys && out_vals) {
                    out_keys[count] = c->fp;
                    out_vals[count] = c->value;
                }
                count++;
            }
        }
    }
    
    *out_num = count;
}

Elastic_2FASketch* sketch_create(uint32_t bucket_num, uint32_t thres_set) {
    Elastic_2FASketch* sketch = malloc(sizeof(Elastic_2FASketch));
    if (!sketch) return NULL;
    
    sketch->hp.buckets = calloc(bucket_num, sizeof(Bucket));
    if (!sketch->hp.buckets) {
        free(sketch);
        return NULL;
    }
    
    sketch->hp.bucket_num = bucket_num;
    sketch->hp.cnt = 0;
    sketch->hp.cnt_all = 0;
    sketch->thres_set = thres_set;
    
    return sketch;
}

void sketch_destroy(Elastic_2FASketch* sketch) {
    if (!sketch) return;
    free(sketch->hp.buckets);
    free(sketch);
}

void sketch_clear(Elastic_2FASketch* sketch) {
    if (!sketch) return;
    heavypart_clear(&sketch->hp);
}

void sketch_insert(Elastic_2FASketch* sketch, const uint8_t* key, uint32_t f) {
    if (!sketch || !key) return;
    
    int res = heavypart_quick_insert(&sketch->hp, key, f, sketch->thres_set);
    
    if (res == (int)sketch->thres_set) {
        heavypart_quick_insert(&sketch->hp, key, f, 0);
    }
}

uint32_t sketch_query(Elastic_2FASketch* sketch, const uint8_t* key) {
    if (!sketch || !key) return 0;
    return heavypart_query(&sketch->hp, key, sketch->thres_set);
}

void sketch_get_heavy_hitters(Elastic_2FASketch* sketch,
                              uint32_t threshold,
                              uint32_t* keys,
                              uint32_t* vals,
                              int* num) {
    if (!sketch) return;
    heavypart_get_heavy_hitters(&sketch->hp, threshold, keys, vals, num);
}

#endif