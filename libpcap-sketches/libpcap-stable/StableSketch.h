#ifndef STABLESKETCH_H
#define STABLESKETCH_H

/* StableSketch.h
 *
 * C conversion of StableSketch.hpp (header-only).
 * Requires:
 *   - datatypes.h (converted C version that defines key_tp, val_tp, mymap/myset/myvector)
 *   - hash.h
 *   - util.h
 *   - uthash.h (if used in datatypes.h)
 *
 * Note: This header defines the data structures and function prototypes.
 *       Implementation of the functions (StableSketch_create, StableSketch_update, ...)
 *       should go into StableSketch.c which we'll create when you provide the cpp body.
 */

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

/* ---------------------------
 * Bucket type (SBucket)
 * --------------------------- */
typedef struct SBUCKET_type {
    int count;
    int stablecount;
    unsigned char key[LGN];
} SBucket;

/* ---------------------------
 * Inner stable_type (equivalent to C++ struct stable_type)
 * --------------------------- */
typedef struct stable_type {
    /* Counter to count total degree */
    val_tp sum;

    /* Counter table: depth x width table of SBucket*.
       We'll store as SBucket** (array of pointers to rows), where each row is an array of SBucket of length width.
       In memory it will typically be allocated as:
           SBucket *all = malloc(depth * width * sizeof(SBucket));
           SBucket **counts = malloc(depth * sizeof(SBucket*));
           for (i) counts[i] = all + i*width;
    */
    SBucket **counts;

    /* Outer sketch depth and width */
    int depth;
    int width;

    /* # key word bits */
    int lgn;

    /* Hash seeds / params. We use unsigned long here to mimic original.
       You may want to use uint64_t if you prefer fixed width. */
    unsigned long *hash;
    unsigned long *scale;
    unsigned long *hardner;
} stable_type;

/* Forward declaration for StableSketch */
typedef struct StableSketch StableSketch;

/* ---------------------------
 * StableSketch struct
 * --------------------------- */
struct StableSketch {
    stable_type stable_;
    /* Additional internal fields can be added here if needed (e.g., counters, mutexes) */
};

/* ---------------------------
 * Constructor / Destructor
 * --------------------------- */

/**
 * Create a StableSketch object.
 * Parameters:
 *   depth - number of rows
 *   width - number of buckets per row
 *   lgn   - key length (bits/bytes used by the algorithm). In original LGN is a macro (8).
 * Returns:
 *   pointer to allocated StableSketch (NULL on failure)
 */
StableSketch* StableSketch_create(int depth, int width, int lgn);

/**
 * Free StableSketch and all allocated sub-structures.
 */
void StableSketch_destroy(StableSketch* ss);

/* ---------------------------
 * Core methods (C equivalents)
 * --------------------------- */

/**
 * Update the sketch with key (byte array of length LGN) and value.
 */
void StableSketch_Update(StableSketch* ss, unsigned char* key, val_tp value);

/**
 * Point query for a key. Returns estimated count (val_tp).
 */
val_tp StableSketch_PointQuery(StableSketch* ss, unsigned char* key);

/**
 * Query the sketch for items above thresh and append results into `results` (myvector).
 * The myvector must be initialized by the caller (myvector_init).
 */
void StableSketch_Query(StableSketch* ss, val_tp thresh, myvector* results);

/**
 * Move to a new window (reset per-window counters as required by algorithm).
 * Semantics should match original C++ NewWindow().
 */
void StableSketch_NewWindow(StableSketch* ss);

/**
 * Lower estimation for the given key (algorithm-specific).
 */
val_tp StableSketch_Low_estimate(StableSketch* ss, unsigned char* key);

/**
 * Upper estimation for the given key (algorithm-specific).
 */
val_tp StableSketch_Up_estimate(StableSketch* ss, unsigned char* key);

/**
 * Get global count (total sum) stored in the sketch.
 */
val_tp StableSketch_GetCount(StableSketch* ss);

/**
 * Reset the sketch to empty (zero out buckets but keep structure).
 */
void StableSketch_Reset(StableSketch* ss);

/**
 * Merge an array of StableSketch pointers into destination `ss`.
 * Equivalent to C++ MergeAll(StableSketch** stable_arr, int size).
 * Behavior: Merge `size` sketches in the array `stable_arr` into `ss` (ss must be allocated).
 */
void StableSketch_MergeAll(StableSketch* ss, StableSketch** stable_arr, int size);

/* ---------------------------
 * Low-level helpers / accessors
 * --------------------------- */

/**
 * Set bucket at (row, column) with provided fields.
 * This mirrors the private SetBucket in C++.
 */
void StableSketch_SetBucket(StableSketch* ss, int row, int column, val_tp sum, long count, unsigned char* key);

/**
 * Get the internal counts table pointer.
 * Returns pointer to SBucket** (depth pointers to rows).
 */
SBucket** StableSketch_GetTable(StableSketch* ss);

/* ---------------------------
 * Utility functions (optional)
 * --------------------------- */

/**
 * Initialize stable_type fields to safe defaults (no allocation).
 * Usually used internally by create; exposed for testing if needed.
 */
void stable_type_init(stable_type* s);

/**
 * Free memory owned by stable_type (does not free stable_type itself).
 */
void stable_type_free(stable_type* s);

#ifdef __cplusplus
}
#endif

#endif /* STABLESKETCH_H */
