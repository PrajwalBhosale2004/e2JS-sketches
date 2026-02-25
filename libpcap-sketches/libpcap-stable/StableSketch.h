#ifndef STABLESKETCH_H
#define STABLESKETCH_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include "datatypes.h" 
#include "hash.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SBUCKET_type {
    int count;
    int stablecount;
    unsigned char key[LGN];
} SBucket;


typedef struct stable_type {
    val_tp sum;

    SBucket **counts;

    int depth;
    int width;

    int lgn;

    unsigned long *hash;
    unsigned long *scale;
    unsigned long *hardner;
} stable_type;

typedef struct StableSketch StableSketch;

struct StableSketch {
    stable_type stable_;
};


StableSketch* StableSketch_create(int depth, int width, int lgn);

void StableSketch_destroy(StableSketch* ss);

void StableSketch_Update(StableSketch* ss, unsigned char* key, val_tp value);

val_tp StableSketch_PointQuery(StableSketch* ss, unsigned char* key);

void StableSketch_Query(StableSketch* ss, val_tp thresh, myvector* results);

void StableSketch_NewWindow(StableSketch* ss);

val_tp StableSketch_Low_estimate(StableSketch* ss, unsigned char* key);

val_tp StableSketch_Up_estimate(StableSketch* ss, unsigned char* key);

val_tp StableSketch_GetCount(StableSketch* ss);

void StableSketch_Reset(StableSketch* ss);

void StableSketch_MergeAll(StableSketch* ss, StableSketch** stable_arr, int size);

void StableSketch_SetBucket(StableSketch* ss, int row, int column, val_tp sum, long count, unsigned char* key);

SBucket** StableSketch_GetTable(StableSketch* ss);

void stable_type_init(stable_type* s);

void stable_type_free(stable_type* s);

#ifdef __cplusplus
}
#endif

#endif
