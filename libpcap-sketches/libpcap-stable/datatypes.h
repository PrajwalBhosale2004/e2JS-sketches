#ifndef DATATYPE_H
#define DATATYPE_H

#include "hash.h"
#include <stdint.h>
#include <string.h>
#include "uthash.h"   // external library for hash map/set

#define LGN 13

// -----------------------------
// Key + Value
// -----------------------------
typedef struct {
    unsigned char key[LGN];
} key_tp;

typedef uint64_t val_tp;

// Hash function for key_tp
static inline uint64_t key_tp_hash(const key_tp *k) {
    return MurmurHash64A(k->key, LGN, 388650253);
}

// Equality check for key_tp
static inline int key_tp_eq(const key_tp *x, const key_tp *y) {
    return (memcmp(x->key, y->key, LGN) == 0);
}

// -----------------------------
// unordered_set<key_tp>
// -----------------------------
typedef struct myset_entry {
    key_tp key;
    UT_hash_handle hh;   // makes this struct hashable
} myset_entry;

typedef myset_entry* myset;

// Functions for set
static inline void myset_add(myset *set, key_tp key) {
    myset_entry *e;
    HASH_FIND(hh, *set, key.key, LGN, e);
    if (e == NULL) {
        e = (myset_entry*)malloc(sizeof(myset_entry));
        memcpy(&e->key, &key, sizeof(key_tp));
        HASH_ADD_KEYPTR(hh, *set, e->key.key, LGN, e);
    }
}

static inline int myset_contains(myset set, key_tp key) {
    myset_entry *e;
    HASH_FIND(hh, set, key.key, LGN, e);
    return (e != NULL);
}

static inline void myset_free(myset *set) {
    myset_entry *curr, *tmp;
    HASH_ITER(hh, *set, curr, tmp) {
        HASH_DEL(*set, curr);
        free(curr);
    }
}

// -----------------------------
// unordered_map<key_tp, val_tp>
// -----------------------------
typedef struct mymap_entry {
    key_tp key;
    val_tp val;
    UT_hash_handle hh;   // makes this struct hashable
} mymap_entry;

typedef mymap_entry* mymap;

// Functions for map
static inline void mymap_put(mymap *map, key_tp key, val_tp val) {
    mymap_entry *e;
    HASH_FIND(hh, *map, key.key, LGN, e);
    if (e == NULL) {
        e = (mymap_entry*)malloc(sizeof(mymap_entry));
        memcpy(&e->key, &key, sizeof(key_tp));
        e->val = val;
        HASH_ADD_KEYPTR(hh, *map, e->key.key, LGN, e);
    } else {
        e->val = val; // update
    }
}

static inline int mymap_get(mymap map, key_tp key, val_tp *out) {
    mymap_entry *e;
    HASH_FIND(hh, map, key.key, LGN, e);
    if (e != NULL) {
        *out = e->val;
        return 1;
    }
    return 0;
}

static inline void mymap_free(mymap *map) {
    mymap_entry *curr, *tmp;
    HASH_ITER(hh, *map, curr, tmp) {
        HASH_DEL(*map, curr);
        free(curr);
    }
}

// -----------------------------
// vector<pair<key_tp, val_tp>>
// -----------------------------
typedef struct {
    key_tp key;
    val_tp val;
} keyval_pair;

typedef struct {
    keyval_pair *data;
    size_t size;
    size_t capacity;
} myvector;

// Vector functions
static inline void myvector_init(myvector *v) {
    v->size = 0;
    v->capacity = 16;
    v->data = (keyval_pair*)malloc(v->capacity * sizeof(keyval_pair));
}

static inline void myvector_push(myvector *v, key_tp key, val_tp val) {
    if (v->size == v->capacity) {
        v->capacity *= 2;
        v->data = (keyval_pair*)realloc(v->data, v->capacity * sizeof(keyval_pair));
    }
    v->data[v->size].key = key;
    v->data[v->size].val = val;
    v->size++;
}

static inline void myvector_free(myvector *v) {
    free(v->data);
    v->data = NULL;
    v->size = v->capacity = 0;
}

// -----------------------------
// Flow key & Tuple
// -----------------------------
#pragma pack(push, 1)
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_key_t;

typedef struct {
    flow_key_t key;
    uint16_t size;
} tuple_t;
#pragma pack(pop)

#endif // DATATYPE_H
