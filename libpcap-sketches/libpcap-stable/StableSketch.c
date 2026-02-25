#include "StableSketch.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include "hash.c"
#include "util.h"


#define KEYLEN_BYTES(s) ((s)->stable_.lgn / 8)

StableSketch* StableSketch_create(int depth, int width, int lgn) {
    StableSketch *ss = (StableSketch*)malloc(sizeof(StableSketch));
    if (!ss) return NULL;

    ss->stable_.depth = depth;
    ss->stable_.width = width;
    ss->stable_.lgn = lgn;
    ss->stable_.sum = 0;

    int total = depth * width;
    ss->stable_.counts = (SBucket**)malloc(sizeof(SBucket*) * total);
    if (!ss->stable_.counts) {
        free(ss);
        return NULL;
    }

    for (int i = 0; i < total; i++) {
        ss->stable_.counts[i] = (SBucket*)calloc(1, sizeof(SBucket));
        if (!ss->stable_.counts[i]) {
            for (int j = 0; j < i; ++j) free(ss->stable_.counts[j]);
            free(ss->stable_.counts);
            free(ss);
            return NULL;
        }
        memset(ss->stable_.counts[i], 0, sizeof(SBucket));
        ss->stable_.counts[i]->key[0] = '\0';
    }

    ss->stable_.hash = (unsigned long*)malloc(sizeof(unsigned long) * depth);
    ss->stable_.scale = (unsigned long*)malloc(sizeof(unsigned long) * depth);
    ss->stable_.hardner = (unsigned long*)malloc(sizeof(unsigned long) * depth);
    if (!ss->stable_.hash || !ss->stable_.scale || !ss->stable_.hardner) {
        for (int i = 0; i < total; i++) free(ss->stable_.counts[i]);
        free(ss->stable_.counts);
        free(ss->stable_.hash);
        free(ss->stable_.scale);
        free(ss->stable_.hardner);
        free(ss);
        return NULL;
    }

    char name[] = "StableSketch";
    uint64_t seed = AwareHash((unsigned char*)name, strlen(name), 13091204281ULL, 228204732751ULL, 6620830889ULL);
    for (int i = 0; i < depth; i++) {
        uint64_t v = GenHashSeed(seed++);
        ss->stable_.hash[i] = (unsigned long)v;
    }
    for (int i = 0; i < depth; i++) {
        uint64_t v = GenHashSeed(seed++);
        ss->stable_.scale[i] = (unsigned long)v;
    }
    for (int i = 0; i < depth; i++) {
        uint64_t v = GenHashSeed(seed++);
        ss->stable_.hardner[i] = (unsigned long)v;
    }

    srand((unsigned)time(NULL));

    return ss;
}

void StableSketch_destroy(StableSketch* ss) {
    if (!ss) return;
    int total = ss->stable_.depth * ss->stable_.width;
    for (int i = 0; i < total; i++) {
        if (ss->stable_.counts[i]) {
            free(ss->stable_.counts[i]);
        }
    }
    free(ss->stable_.counts);
    free(ss->stable_.hash);
    free(ss->stable_.scale);
    free(ss->stable_.hardner);
    free(ss);
}

void StableSketch_Update(StableSketch* ss, unsigned char* key, val_tp val) {
    if (!ss || !key) return;

    unsigned long bucket = 0;
    int keylen = ss->stable_.lgn / 8;
    ss->stable_.sum += 1;
    SBucket *sbucket;
    int flag = 0;
    long min = LONG_MAX;
    int loc = -1;
    int k;
    int index;

    for (int i = 0; i < ss->stable_.depth; i++) {
        bucket = (unsigned long)(MurmurHash64A(key, keylen, ss->stable_.hardner[i]) % ss->stable_.width);
        index = i * ss->stable_.width + (int)bucket;
        sbucket = ss->stable_.counts[index];
        if ((sbucket->key[0] == '\0') && (sbucket->count == 0)) {
            memcpy(sbucket->key, key, (size_t)keylen);
            flag = 1;
            sbucket->count = 1;
            sbucket->stablecount = sbucket->stablecount + 1;
            return;
        } else if (memcmp(key, sbucket->key, (size_t)keylen) == 0) {
            flag = 1;
            sbucket->count += 1;
            sbucket->stablecount = sbucket->stablecount + 1;
            return;
        }
        if (sbucket->count < min) {
            min = sbucket->count;
            loc = index;
        }
    }

    if (flag == 0 && loc >= 0) {
        sbucket = ss->stable_.counts[loc];
        int denom = (int)(sbucket->stablecount * (sbucket->count) + 1.0);
        if (denom <= 0) denom = 1;
        k = rand() % denom + 1;
        if (k > (int)((sbucket->count) * sbucket->stablecount)) {
            sbucket->count -= 1;
            if (sbucket->count <= 0) {
                memcpy(sbucket->key, key, (size_t)keylen);
                sbucket->count += 1;
                sbucket->stablecount = sbucket->stablecount - 1;
                if (sbucket->stablecount <= 0) {
                    sbucket->stablecount = 0;
                }
            }
        }
    }
}

void StableSketch_Query(StableSketch* ss, val_tp thresh, myvector* results) {
    if (!ss || !results) return;
    int total = ss->stable_.depth * ss->stable_.width;
    int keylen = ss->stable_.lgn / 8;
    for (int i = 0; i < total; i++) {
        SBucket *b = ss->stable_.counts[i];
        if (b->count > (int)thresh) {
            key_tp reskey;
            memset(&reskey, 0, sizeof(reskey));
            memcpy(reskey.key, b->key, (size_t)keylen);
            myvector_push(results, reskey, (val_tp)b->count);
        }
    }

    fprintf(stdout, "results.size = %zu\n", results->size);
}

val_tp StableSketch_PointQuery(StableSketch* ss, unsigned char* key) {
    return StableSketch_Low_estimate(ss, key);
}

val_tp StableSketch_Low_estimate(StableSketch* ss, unsigned char* key) {
    if (!ss || !key) return 0;
    val_tp max = 0;
    long min = LONG_MAX;
    int keylen = ss->stable_.lgn / 8;

    for (int i = 0; i < ss->stable_.depth; i++) {
        unsigned long bucket = (unsigned long)(MurmurHash64A(key, keylen, ss->stable_.hardner[i]) % ss->stable_.width);
        unsigned long index = (unsigned long)(i * ss->stable_.width + bucket);

        if (memcmp(ss->stable_.counts[index]->key, key, (size_t)keylen) == 0) {
            max += (val_tp)ss->stable_.counts[index]->count;
        }

        /* neighbor bucket (bucket + 1) % width */
        unsigned long index2 = (unsigned long)(i * ss->stable_.width + ((bucket + 1) % ss->stable_.width));
        if (memcmp(ss->stable_.counts[index2]->key, key, (size_t)keylen) == 0) {
            max += (val_tp)ss->stable_.counts[index2]->count;
        }
    }

    return max;
}

val_tp StableSketch_Up_estimate(StableSketch* ss, unsigned char* key) {
    if (!ss || !key) return 0;
    val_tp max = 0;
    long min = LONG_MAX;
    int keylen = ss->stable_.lgn / 8;

    for (int i = 0; i < ss->stable_.depth; i++) {
        unsigned long bucket = (unsigned long)(MurmurHash64A(key, keylen, ss->stable_.hardner[i]) % ss->stable_.width);
        unsigned long index = (unsigned long)(i * ss->stable_.width + bucket);

        if (memcmp(ss->stable_.counts[index]->key, key, (size_t)keylen) == 0) {
            max += (val_tp)ss->stable_.counts[index]->count;
        }
        if (ss->stable_.counts[index]->count < min) min = ss->stable_.counts[index]->count;

        unsigned long index2 = (unsigned long)(i * ss->stable_.width + ((bucket + 1) % ss->stable_.width));
        if (memcmp(ss->stable_.counts[index2]->key, key, (size_t)keylen) == 0) {
            max += (val_tp)ss->stable_.counts[index2]->count;
        }
    }

    if (max) return max;
    return (val_tp) (min == LONG_MAX ? 0 : min);
}

val_tp StableSketch_GetCount(StableSketch* ss) {
    if (!ss) return 0;
    return ss->stable_.sum;
}

void StableSketch_Reset(StableSketch* ss) {
    if (!ss) return;
    ss->stable_.sum = 0;
    int total = ss->stable_.depth * ss->stable_.width;
    int keylen = ss->stable_.lgn / 8;
    for (int i = 0; i < total; i++) {
        ss->stable_.counts[i]->count = 0;
        ss->stable_.counts[i]->stablecount = 0;
        memset(ss->stable_.counts[i]->key, 0, (size_t)keylen);
    }
}

void StableSketch_SetBucket(StableSketch* ss, int row, int column, val_tp sum, long count, unsigned char* key) {
    if (!ss) return;
    int index = row * ss->stable_.width + column;
    if (index < 0 || index >= ss->stable_.depth * ss->stable_.width) return;
    ss->stable_.counts[index]->count = (int)count;
    if (key) {
        memcpy(ss->stable_.counts[index]->key, key, (size_t)(ss->stable_.lgn / 8));
    }
    (void)sum;
}

SBucket** StableSketch_GetTable(StableSketch* ss) {
    if (!ss) return NULL;
    return ss->stable_.counts;
}

void StableSketch_MergeAll(StableSketch* ss, StableSketch** stable_arr, int size) {
    if (!ss || !stable_arr || size <= 0) return;

    int total = ss->stable_.depth * ss->stable_.width;
    for (int s = 0; s < size; s++) {
        StableSketch* other = stable_arr[s];
        if (!other) continue;
        if (other->stable_.depth != ss->stable_.depth || other->stable_.width != ss->stable_.width) {
            continue;
        }
        for (int i = 0; i < total; i++) {
            SBucket *dst = ss->stable_.counts[i];
            SBucket *src = other->stable_.counts[i];
            if (!src) continue;

            int keylen = ss->stable_.lgn / 8;
            int src_empty = (src->count == 0);
            int dst_empty = (dst->count == 0);

            if (src_empty) continue;
            if (dst_empty) {
                dst->count = src->count;
                dst->stablecount = src->stablecount;
                memcpy(dst->key, src->key, (size_t)keylen);
            } else {
                if (memcmp(dst->key, src->key, (size_t)keylen) == 0) {
                    dst->count += src->count;
                    dst->stablecount += src->stablecount;
                } else {
                }
            }
        }
        ss->stable_.sum += other->stable_.sum;
    }
}


void StableSketch_NewWindow(StableSketch* ss) {
    if (!ss) return;
    int total = ss->stable_.depth * ss->stable_.width;
    for (int i = 0; i < total; i++) {
        ss->stable_.counts[i]->stablecount = 0;
    }
}

void stable_type_init(stable_type* s) {
    if (!s) return;
    s->sum = 0;
    s->counts = NULL;
    s->depth = s->width = s->lgn = 0;
    s->hash = s->scale = s->hardner = NULL;
}

void stable_type_free(stable_type* s) {
    if (!s) return;
    if (s->counts) {
        int total = s->depth * s->width;
        for (int i = 0; i < total; ++i) {
            if (s->counts[i]) free(s->counts[i]);
        }
        free(s->counts);
        s->counts = NULL;
    }
    if (s->hash) { free(s->hash); s->hash = NULL; }
    if (s->scale) { free(s->scale); s->scale = NULL; }
    if (s->hardner) { free(s->hardner); s->hardner = NULL; }
    s->depth = s->width = s->lgn = 0;
}
