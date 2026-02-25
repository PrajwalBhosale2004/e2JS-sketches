#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#include "MurmurHash3.c"

#define KEY_SIZE 13
#define CELL_NUM_H 4
#define CELL_NUM_L 4
#define BUCKET_NUM 567
#define LEFT_PART_BITS 79
#define EXTRA_BITS_NUM 2
#define COM_BYTES 10

#define CELLS_PER_BUCKET (CELL_NUM_H + CELL_NUM_L)
#define SLOT_LENGTH_BITS (LEFT_PART_BITS + EXTRA_BITS_NUM)
#define EXTRA_MAX ((1u << EXTRA_BITS_NUM) - 1u)
#define AL_THRESHOLD 512u

#define MASK_26BITS 0x3FFFFFF
#define MI_A 2147483647
#define MI_A_INV 4503597479886847
#define MI_MASK 4503599627370495

static inline uint64_t total_heavy_slots(void) {
    return ((uint64_t)BUCKET_NUM) * ((uint64_t)CELL_NUM_H);
}


typedef struct {
    uint16_t FP; 
    uint32_t C;  
} bucket_cell_t;


typedef struct {
    bucket_cell_t bucketArray[BUCKET_NUM][CELLS_PER_BUCKET]; 
    uint64_t *auxiliaryList; 
    size_t aux_word_count; 
} sketch_t;


void divideKey(const uint8_t key[KEY_SIZE], uint32_t *out_bucket_idx, uint16_t *out_fp, uint64_t leftPart[2]) {
    
    memcpy(leftPart, key, KEY_SIZE);
    
    
    
    uint64_t part1 = leftPart[0] & MI_MASK;
    uint64_t part2 = (leftPart[1] << 12) + (leftPart[0] >> 52);
    part1 = (part1 * MI_A) & MI_MASK;
    part2 = (part2 * MI_A) & MI_MASK;
    
    uint32_t tempParts[2] = {0};
    tempParts[0] = (uint32_t)(part1 & MASK_26BITS) ^ (uint32_t)(part1 >> 26) ^ (uint32_t)(part2 & MASK_26BITS);
    tempParts[1] = tempParts[0] ^ (uint32_t)(part2 >> 26);
    tempParts[1] ^= tempParts[1] >> 13;
    
    leftPart[0] = part1 + ((uint64_t)(tempParts[0] & 0xFFF) << 52);
    leftPart[1] = (tempParts[1]) + (((uint64_t)tempParts[0] & (~0xFFF)) << 14);
    
    
    uint32_t index = leftPart[1] % BUCKET_NUM;
    leftPart[1] /= BUCKET_NUM;
    
    
    uint16_t fingerprint = leftPart[1] & 0xFFFF;
    leftPart[1] >>= 16; 
    
    if (out_bucket_idx) *out_bucket_idx = index;
    if (out_fp) *out_fp = fingerprint;
}

void combineKey(uint8_t out_key[KEY_SIZE], uint32_t index, uint16_t fingerprint, const uint64_t leftPart[2]) {
    uint64_t localLeftPart[2];
    localLeftPart[0] = leftPart[0];
    localLeftPart[1] = leftPart[1];
    
    
    localLeftPart[1] = ((localLeftPart[1] << 16) + fingerprint) * BUCKET_NUM + index;
    
    uint32_t tempParts[2] = {0};
    tempParts[0] = (localLeftPart[0] >> 52) + ((localLeftPart[1] >> 26) << 12);
    tempParts[1] = localLeftPart[1] & 0x3FFFFFF;
    
    tempParts[1] = ((tempParts[1] & 0x1FFF) ^ (tempParts[1] >> 13)) + (tempParts[1] & (~0x1FFF));
    
    uint64_t part1 = localLeftPart[0] & MI_MASK;
    uint64_t part2 = 0;
    
    part2 += tempParts[1] ^ tempParts[0];
    part2 <<= 26;
    part2 += tempParts[0] ^ (uint32_t)(part1 & MASK_26BITS) ^ (uint32_t)(part1 >> 26);
    
    
    part1 = (part1 * MI_A_INV) & MI_MASK;
    part2 = (part2 * MI_A_INV) & MI_MASK;
    
    localLeftPart[0] = part1 + ((part2 & 0xFFF) << 52);
    localLeftPart[1] = part2 >> 12;
    
    
    memcpy(out_key, localLeftPart, KEY_SIZE);
}

static void read_bits_from_aux(const sketch_t *sk, uint64_t bit_idx, unsigned nbits, uint64_t out_lo_hi[2]){
    out_lo_hi[0] = 0;
    out_lo_hi[1] = 0;
    if(nbits == 0) return;

    uint64_t word_idx = bit_idx >> 6;
    unsigned offset = (unsigned)(bit_idx & 63ULL);

    unsigned bits_consumed = 0;

    __uint128_t acc = 0;
    unsigned acc_bits = 0;

    while(bits_consumed < nbits){
        if(word_idx >= sk->aux_word_count) break;

        uint64_t w = sk->auxiliaryList[word_idx];

        uint64_t chunk = w >> offset;
        unsigned avail = 64 - offset;

        unsigned need = (unsigned)(nbits - bits_consumed);
        unsigned take = (need < avail) ? need : avail;

        uint64_t mask = (take == 64) ? (uint64_t)(~0ULL) : ((1ULL << take) - 1ULL);
        uint64_t piece = chunk & mask;

        acc |= (__uint128_t)piece << acc_bits;
        acc_bits += take;
        bits_consumed += take;

        if (take < avail) {
            offset += take;
        } else {
            word_idx += 1;
            offset = 0;
        }
    }

    out_lo_hi[0] = (uint64_t)(acc & (__uint128_t)0xFFFFFFFFFFFFFFFFULL);
    out_lo_hi[1] = (uint64_t)((acc >> 64) & (__uint128_t)0xFFFFFFFFFFFFFFFFULL);
}


static void write_bits_to_aux(sketch_t *sk, uint64_t bit_idx, unsigned nbits, const uint64_t in_lo_hi[2]) {
    if (nbits == 0) return;

    __uint128_t val = (__uint128_t)in_lo_hi[0] | ((__uint128_t)in_lo_hi[1] << 64);

    uint64_t word_idx = bit_idx >> 6;
    unsigned offset = (unsigned)(bit_idx & 63ULL);

    unsigned bits_written = 0;
    unsigned remaining = nbits;

    while (bits_written < nbits) {
        if (word_idx >= sk->aux_word_count) {
            break;
        }

        unsigned avail = 64 - offset;
        unsigned to_write = (remaining < avail) ? remaining : avail;

        uint64_t dstmask;
        if (to_write == 64 && offset == 0) {
            dstmask = ~0ULL; 
        } else {
            uint64_t mask_low = (to_write == 64) ? (~0ULL) : ((1ULL << to_write) - 1ULL);
            dstmask = mask_low << offset;
        }


        __uint128_t piece = (val >> bits_written) & (__uint128_t)((to_write == 64) ? (~0ULL) : ((1ULL << to_write) - 1ULL));
        uint64_t piece32 = (uint64_t)piece;

        uint64_t dst = sk->auxiliaryList[word_idx];
        dst &= ~dstmask;
        dst |= (uint64_t)(piece32 << offset);
        sk->auxiliaryList[word_idx] = dst;

        bits_written += to_write;
        remaining -= to_write;
        word_idx += (offset + to_write) / 64;
        offset = (offset + to_write) % 64;
    }
}

void setLeftPart(sketch_t *sk, uint32_t slot_idx, const uint64_t leftPart[2]) {
    if (!sk || !sk->auxiliaryList) return;
    uint64_t bit_idx = (uint64_t)slot_idx * (uint64_t)SLOT_LENGTH_BITS;
    __uint128_t val = (__uint128_t)leftPart[0] | ((__uint128_t)leftPart[1] << 64);
    if (LEFT_PART_BITS < 128) {
        val &= (((__uint128_t)1 << LEFT_PART_BITS) - 1);
    }
    uint64_t in_lo_hi[2];
    in_lo_hi[0] = (uint64_t)(val & (__uint128_t)0xFFFFFFFFFFFFFFFFULL);
    in_lo_hi[1] = (uint64_t)((val >> 64) & (__uint128_t)0xFFFFFFFFFFFFFFFFULL);
    write_bits_to_aux(sk, bit_idx, (unsigned)LEFT_PART_BITS, in_lo_hi);
}

void setLeftPartCounter(sketch_t *sk, uint32_t slot_idx, uint8_t counter) {
    if (!sk || !sk->auxiliaryList) return;
    uint64_t bit_idx = (uint64_t)slot_idx * (uint64_t)SLOT_LENGTH_BITS + (uint64_t)LEFT_PART_BITS;
    uint64_t in_lo_hi[2];
    in_lo_hi[0] = (uint64_t)(counter & ((1u << EXTRA_BITS_NUM) - 1u));
    in_lo_hi[1] = 0;
    write_bits_to_aux(sk, bit_idx, (unsigned)EXTRA_BITS_NUM, in_lo_hi);
}

void getLeftPart(sketch_t *sk, uint32_t slot_idx, uint64_t outLeftPart[2], uint8_t *out_extra_bits) {
    if (!sk || !sk->auxiliaryList) {
        outLeftPart[0] = outLeftPart[1] = 0;
        if (out_extra_bits) *out_extra_bits = 0;
        return;
    }
    uint64_t bit_idx = (uint64_t)slot_idx * (uint64_t)SLOT_LENGTH_BITS;
    uint64_t lohi[2];
    read_bits_from_aux(sk, bit_idx, (unsigned)LEFT_PART_BITS, lohi);
    outLeftPart[0] = lohi[0];
    outLeftPart[1] = lohi[1];

    uint64_t extra_lohi[2];
    read_bits_from_aux(sk, bit_idx + (uint64_t)LEFT_PART_BITS, (unsigned)EXTRA_BITS_NUM, extra_lohi);
    if (out_extra_bits) {
        *out_extra_bits = (uint8_t)(extra_lohi[0] & ((1u << EXTRA_BITS_NUM) - 1u));
    }
}

static int compare_leftparts_by_bytes(const uint64_t a[2], const uint64_t b[2]) {
    uint8_t buf_a[COM_BYTES];
    uint8_t buf_b[COM_BYTES];

    __uint128_t vala = (__uint128_t)a[0] | ((__uint128_t)a[1] << 64);
    __uint128_t valb = (__uint128_t)b[0] | ((__uint128_t)b[1] << 64);

    for (int i = 0; i < COM_BYTES; ++i) {
        buf_a[i] = (uint8_t)(vala & (__uint128_t)0xFFu);
        vala >>= 8;
        buf_b[i] = (uint8_t)(valb & (__uint128_t)0xFFu);
        valb >>= 8;
    }
    return (memcmp(buf_a, buf_b, COM_BYTES) == 0) ? 1 : 0;
}

void sketch_insert(sketch_t *sk, const uint8_t key[KEY_SIZE]) {
    if (!sk) return;

    uint32_t bucketIdx;
    uint16_t fp;
    uint64_t leftPart[2];
    divideKey(key, &bucketIdx, &fp, leftPart);

    
    int matched_idx = -1;           

    int smallest_heavy_idx = 0;
    uint32_t smallest_heavy_c = UINT32_MAX;

    int smallest_idx = 0;
    uint32_t smallest_c = UINT32_MAX;

    
    for (int j = 0; j < CELL_NUM_H; ++j) {
        bucket_cell_t *cell = &sk->bucketArray[bucketIdx][j];
        uint32_t c = cell->C;
        
        if (c < smallest_heavy_c) {
            smallest_heavy_c = c;
            smallest_heavy_idx = j;
        }
        
        if (c < smallest_c) {
            smallest_c = c;
            smallest_idx = j;
        }
        
        if (c == 0) {
            cell->FP = fp;
            cell->C = 1;
            uint32_t slot_idx = bucketIdx * CELL_NUM_H + j;
            setLeftPart(sk, slot_idx, leftPart);           
            setLeftPartCounter(sk, slot_idx, 0);           
            return;
        }
        if (cell->FP == fp) {
            matched_idx = j;
            break;
        }
    }

    
    if (matched_idx >= 0) {
        bucket_cell_t *cell = &sk->bucketArray[bucketIdx][matched_idx];
        cell->C += 1;
        uint32_t newc = cell->C;

        int do_alupdate = 0;
        if (newc == AL_THRESHOLD) do_alupdate = 1;
        else if (newc > AL_THRESHOLD) {
            if (rand() % AL_THRESHOLD == 0) do_alupdate = 1;
        }

        if (do_alupdate) {
            uint32_t slot_idx = bucketIdx * CELL_NUM_H + matched_idx;
            uint64_t storedLP[2];
            uint8_t extraS = 0;
            getLeftPart(sk, slot_idx, storedLP, &extraS);

            if (compare_leftparts_by_bytes(storedLP, leftPart)) {
                
                if (extraS < EXTRA_MAX) extraS++;
                setLeftPartCounter(sk, slot_idx, extraS);
            } else {
                
                if (extraS > 0) {
                    extraS--;
                    setLeftPartCounter(sk, slot_idx, extraS);
                } else {
                    
                    setLeftPart(sk, slot_idx, leftPart);
                    setLeftPartCounter(sk, slot_idx, 0);
                }
            }
        }
        return;
    }

    
    for (int j = CELL_NUM_H; j < CELLS_PER_BUCKET; ++j) {
        bucket_cell_t *cell = &sk->bucketArray[bucketIdx][j];
        uint32_t c = cell->C;
        if (c < smallest_c) {
            smallest_c = c;
            smallest_idx = j;
        }
        if (c == 0) {
            
            cell->FP = fp;
            cell->C = 1;
            return;
        }
        if (cell->FP == fp) {
            
            cell->C += 1;
            
            if (cell->C >= smallest_heavy_c) {
                
                bucket_cell_t tmp = sk->bucketArray[bucketIdx][smallest_heavy_idx];
                sk->bucketArray[bucketIdx][smallest_heavy_idx] = *cell;
                *cell = tmp;
                
                uint32_t new_heavy_idx = smallest_heavy_idx;
                uint32_t slot_idx = bucketIdx * CELL_NUM_H + new_heavy_idx;
                setLeftPart(sk, slot_idx, leftPart);       
                setLeftPartCounter(sk, slot_idx, 0);
            }
            return;
        }
    }

    
    if (smallest_c == 0) {
        
        int idx = smallest_idx;
        sk->bucketArray[bucketIdx][idx].FP = fp;
        sk->bucketArray[bucketIdx][idx].C = 1;
        if (idx < CELL_NUM_H) {
            uint32_t slot_idx = bucketIdx * CELL_NUM_H + idx;
            setLeftPart(sk, slot_idx, leftPart);
            setLeftPartCounter(sk, slot_idx, 0);
        }
        return;
    }

    
    if ((rand() % smallest_c) == 0) {
        int idx = smallest_idx;
        sk->bucketArray[bucketIdx][idx].FP = fp;
        

        
        if (idx < CELL_NUM_H) {
            uint32_t slot_idx = bucketIdx * CELL_NUM_H + idx;
            setLeftPart(sk, slot_idx, leftPart);
            setLeftPartCounter(sk, slot_idx, 0);
        }
    }
}

typedef struct ht_entry {
    uint8_t key[KEY_SIZE];
    uint32_t count;
    struct ht_entry *next;
} ht_entry_t;

typedef struct {
    ht_entry_t **buckets;
    size_t num_buckets; 
    size_t n_entries;
} ht_t;

static ht_t actual_ht = {0};


static size_t next_pow2(size_t x) {
    size_t p = 1;
    while (p < x) p <<= 1;
    return p;
}

int ht_init_with_hint(ht_t *ht, size_t expected_keys) {
    if (!ht) return -1;
    size_t buckets = next_pow2((expected_keys > 0 ? (expected_keys * 2) : 1024));
    if (buckets < 1024) buckets = 1024;
    ht->num_buckets = buckets;
    ht->buckets = (ht_entry_t **) calloc(ht->num_buckets, sizeof(ht_entry_t *));
    if (!ht->buckets) return -1;
    ht->n_entries = 0;
    return 0;
}

void ht_free(ht_t *ht) {
    if (!ht || !ht->buckets) return;
    for (size_t i = 0; i < ht->num_buckets; ++i) {
        ht_entry_t *e = ht->buckets[i];
        while (e) {
            ht_entry_t *n = e->next;
            free(e);
            e = n;
        }
    }
    free(ht->buckets);
    ht->buckets = NULL;
    ht->num_buckets = 0;
    ht->n_entries = 0;
}


void ht_increment(ht_t *ht, const uint8_t key[KEY_SIZE]) {
    if (!ht || !ht->buckets) return;
    uint32_t hashv;
    MurmurHash3_x86_32((const void*)key, KEY_SIZE, 0, &hashv);
    size_t idx = (size_t)hashv & (ht->num_buckets - 1); 
    ht_entry_t *e = ht->buckets[idx];
    while (e) {
        if (memcmp(e->key, key, KEY_SIZE) == 0) {
            e->count++;
            return;
        }
        e = e->next;
    }
    
    ht_entry_t *ne = (ht_entry_t*) malloc(sizeof(ht_entry_t));
    if (!ne) return;
    memcpy(ne->key, key, KEY_SIZE);
    ne->count = 1;
    ne->next = ht->buckets[idx];
    ht->buckets[idx] = ne;
    ht->n_entries++;
}


uint32_t ht_get_count(ht_t *ht, const uint8_t key[KEY_SIZE]) {
    if (!ht || !ht->buckets) return 0;
    uint32_t hashv;
    MurmurHash3_x86_32((const void*)key, KEY_SIZE, 0, &hashv);
    size_t idx = (size_t)hashv & (ht->num_buckets - 1);
    ht_entry_t *e = ht->buckets[idx];
    while (e) {
        if (memcmp(e->key, key, KEY_SIZE) == 0) return e->count;
        e = e->next;
    }
    return 0;
}

/* collect all entries into arrays (caller provides pointers + capacity)
   returns number of items written (or needed if capacity too small).
*/
size_t ht_collect_all(ht_t *ht, uint8_t **out_keys, uint32_t *out_counts, size_t capacity) {
    if (!ht || !ht->buckets) return 0;
    size_t written = 0;
    for (size_t i = 0; i < ht->num_buckets && written < capacity; ++i) {
        ht_entry_t *e = ht->buckets[i];
        while (e && written < capacity) {
            memcpy(out_keys[written], e->key, KEY_SIZE);
            out_counts[written] = e->count;
            written++;
            e = e->next;
        }
    }
    
    return written;
}


size_t sketch_get_estimates(sketch_t *sk, uint8_t **out_keys, uint32_t *out_counts, size_t capacity) {
    if (!sk || !out_keys || !out_counts) return 0;
    size_t written = 0;
    
    for (uint32_t b = 0; b < BUCKET_NUM && written < capacity; ++b) {
        for (int j = 0; j < CELL_NUM_H && written < capacity; ++j) {
            bucket_cell_t *cell = &sk->bucketArray[b][j];
            if (cell->C == 0) continue; 
            
            uint32_t slot_idx = b * CELL_NUM_H + j;
            uint64_t leftPart[2] = {0,0};
            uint8_t extra = 0;
            getLeftPart(sk, slot_idx, leftPart, &extra);
            uint8_t *kbuf = out_keys[written]; 
            combineKey(kbuf, b, cell->FP, leftPart);
            out_counts[written] = cell->C;
            written++;
        }
    }
    return written;
}

size_t read_in_traces(const char *filename, uint8_t ***out_keys) {
    if (!filename || !out_keys) return 0;
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "read_in_traces: cannot open %s\n", filename);
        return 0;
    }
    
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long fsz = ftell(f);
    if (fsz <= 0) { fclose(f); return 0; }
    rewind(f);
    size_t n_items = (size_t) (fsz / KEY_SIZE);
    if (n_items == 0) { fclose(f); return 0; }

    
    uint8_t **keys = (uint8_t **) malloc(sizeof(uint8_t*) * n_items);
    if (!keys) { fclose(f); return 0; }

    
    if (ht_init_with_hint(&actual_ht, n_items) != 0) {
        fprintf(stderr, "read_in_traces: failed to init ht\n");
        free(keys);
        fclose(f);
        return 0;
    }

    
    size_t nread = 0;
    for (size_t i = 0; i < n_items; ++i) {
        uint8_t *buf = (uint8_t*) malloc(KEY_SIZE);
        if (!buf) break;
        size_t r = fread(buf, 1, KEY_SIZE, f);
        if (r != KEY_SIZE) {
            free(buf);
            break;
        }
        keys[nread++] = buf;
        
        ht_increment(&actual_ht, buf);
    }
    fclose(f);

    *out_keys = keys;
    return nread;
}

int sketch_init(sketch_t *sk){
    if(!sk) return -1;

    memset(sk->bucketArray, 0, sizeof(sk->bucketArray));

    uint64_t slots = total_heavy_slots();
    uint64_t total_bits = slots * (uint64_t)SLOT_LENGTH_BITS;
    uint64_t words = (total_bits + 63) / 64;
    sk->aux_word_count = (size_t) words;

    sk->auxiliaryList = (uint64_t*) calloc(sk->aux_word_count, sizeof(uint64_t));
    if(!sk->auxiliaryList){
        fprintf(stderr, "sketch_init: failed to alloc auxiliaryList (%zu words)\n", sk->aux_word_count);
        return -1;
    }
    return 0;
}

void sketch_free(sketch_t *sk){
    if(!sk) return;
    if(sk->auxiliaryList){
        free(sk->auxiliaryList);
        sk->auxiliaryList = NULL;
    }
    sk->aux_word_count = 0;
}

static double timespec_to_seconds(const struct timespec *t) {
    return (double)t->tv_sec + (double)t->tv_nsec / 1e9;
}

int cmp_counts_desc(const void *a, const void *b) {
    const uint32_t *pa = (const uint32_t*) a;
    const uint32_t *pb = (const uint32_t*) b;
    
    if (*pa < *pb) return 1;
    if (*pa > *pb) return -1;
    return 0;
}


typedef struct {
    uint8_t key[KEY_SIZE];
    uint32_t count;
} pair_t;

int pair_cmp_desc(const void *a, const void *b) {
    const pair_t *pa = a;
    const pair_t *pb = b;
    if (pa->count < pb->count) return 1;
    if (pa->count > pb->count) return -1;
    return 0;
}































































































































