/* The MIT License

   Copyright (C) 2012 Zilong Tan (eric.zltan@gmail.com)

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation
   files (the "Software"), to deal in the Software without
   restriction, including without limitation the rights to use, copy,
   modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#ifndef __UNIFIED_HASH_H__
#define __UNIFIED_HASH_H__

static __attribute__((always_inline)) inline __u32 get_hash_signature(void) {
    #ifdef USE_BOBHASH
    return 0xB0B0B0B0;  
    #else
    return 0xFA57FA57;  
    #endif
}

static __attribute__((always_inline)) inline __u64 fasthash_mix(__u64 h) {
    h ^= h >> 23;
    h *= 0x2127599bf4325c37ULL;
    h ^= h >> 47;
    return h;
}

static __attribute__((always_inline)) inline __u64 fasthash64(const void *buf, __u64 len, __u64 seed)
{
    const __u64 m = 0x880355f21e6d1965ULL;
    const __u64 *pos = (const __u64 *)buf;
    const __u64 *end = pos + (len / 8);
    const unsigned char *pos2;
    __u64 h = seed ^ (len * m);
    __u64 v;

    while (pos != end) {
        v  = *pos++;
        h ^= fasthash_mix(v);
        h *= m;
    }

    pos2 = (const unsigned char*)pos;
    v = 0;

    switch (len & 7) {
    case 7: v ^= (__u64)pos2[6] << 48;
    case 6: v ^= (__u64)pos2[5] << 40;
    case 5: v ^= (__u64)pos2[4] << 32;
    case 4: v ^= (__u64)pos2[3] << 24;
    case 3: v ^= (__u64)pos2[2] << 16;
    case 2: v ^= (__u64)pos2[1] << 8;
    case 1: v ^= (__u64)pos2[0];
        h ^= fasthash_mix(v);
        h *= m;
    }

    return fasthash_mix(h);
}

static __attribute__((always_inline)) inline __u32 fasthash32(const void *buf, __u64 len, __u32 seed)
{
    __u64 h = fasthash64(buf, len, seed);
    return h - (h >> 32);
}

static __attribute__((always_inline)) inline __u64 fasthash64_13bytes(const __u8* key, __u64 seed) {
    const __u64 m = 0x880355f21e6d1965ULL;
    __u64 h = seed ^ (13 * m);
    __u64 v;
    
    v = ((__u64)key[0]) | ((__u64)key[1] << 8) |
        ((__u64)key[2] << 16) | ((__u64)key[3] << 24) |
        ((__u64)key[4] << 32) | ((__u64)key[5] << 40) |
        ((__u64)key[6] << 48) | ((__u64)key[7] << 56);
    h ^= fasthash_mix(v);
    h *= m;
    
    v = ((__u64)key[8]) | ((__u64)key[9] << 8) |
        ((__u64)key[10] << 16) | ((__u64)key[11] << 24) |
        ((__u64)key[12] << 32);
    h ^= fasthash_mix(v);
    h *= m;
    
    return fasthash_mix(h);
}

static __attribute__((always_inline)) inline __u32 fasthash32_13bytes(const __u8* key, __u32 seed) {
    __u64 h = fasthash64_13bytes(key, seed);
    return h - (h >> 32);
}

static __attribute__((always_inline)) inline __u32 bob_rotl32(__u32 x, __u8 r) {
    return (x << r) | (x >> (32 - r));
}

static __attribute__((always_inline)) inline __u32 bobhash32_13bytes(const __u8* key, __u32 seed) {
    #define BOB_PRIME2 0x85EBCA77
    #define BOB_PRIME3 0xC2B2AE3D
    #define BOB_PRIME4 0x27D4EB2F
    #define BOB_PRIME5 0x165667B1
    #define BOB_PRIME6 0x9E3779B9
    
    __u32 h = seed ^ 13;
    __u32 k;
    
    k = ((__u32)key[0]) | ((__u32)key[1] << 8) | 
        ((__u32)key[2] << 16) | ((__u32)key[3] << 24);
    k *= BOB_PRIME2;
    k = bob_rotl32(k, 15);
    k *= BOB_PRIME3;
    h ^= k;
    h = bob_rotl32(h, 13);
    h = h * 5 + BOB_PRIME4;
    
    k = ((__u32)key[4]) | ((__u32)key[5] << 8) | 
        ((__u32)key[6] << 16) | ((__u32)key[7] << 24);
    k *= BOB_PRIME2;
    k = bob_rotl32(k, 15);
    k *= BOB_PRIME3;
    h ^= k;
    h = bob_rotl32(h, 13);
    h = h * 5 + BOB_PRIME4;
    
    k = ((__u32)key[8]) | ((__u32)key[9] << 8) | 
        ((__u32)key[10] << 16) | ((__u32)key[11] << 24);
    k *= BOB_PRIME2;
    k = bob_rotl32(k, 15);
    k *= BOB_PRIME3;
    h ^= k;
    h = bob_rotl32(h, 13);
    h = h * 5 + BOB_PRIME4;
    
    k = (__u32)key[12];
    k *= BOB_PRIME2;
    k = bob_rotl32(k, 15);
    k *= BOB_PRIME3;
    h ^= k;
    
    h ^= 13;
    h ^= h >> 16;
    h *= BOB_PRIME5;
    h ^= h >> 13;
    h *= BOB_PRIME6;
    h ^= h >> 16;
    
    return h;
}

#define FASTHASH_SEED_PRIMARY_64 0x9E3779B97F4A7C15ULL
#define FASTHASH_SEED_BACKUP_64  0x517CC1B727220A95ULL
#define FASTHASH_SEED_TERTIARY_64 0xC2B2AE3D7A2E4C1FULL
#define FASTHASH_SEED_QUATERNARY_64 0x85EBCA77B3E6F8A1ULL

static __attribute__((always_inline)) inline __u32 hash_primary(const __u8* key, __u32 bucket_num) {
    #ifdef USE_BOBHASH
    return bobhash32_13bytes(key, 0xCAFEBABE) % bucket_num;
    #else
    return fasthash32_13bytes(key, 0xCAFEBABE) % bucket_num;
    #endif
}

static __attribute__((always_inline)) inline __u32 hash_backup(const __u8* key, __u32 bucket_num) {
    #ifdef USE_BOBHASH
    return bobhash32_13bytes(key, 0xDEADBEEF) % bucket_num;
    #else
    return fasthash32_13bytes(key, 0xDEADBEEF) % bucket_num;
    #endif
}

static __attribute__((always_inline)) inline __u32 hash_primary_64(const __u8* key, __u32 bucket_num) {
    #ifdef USE_BOBHASH
    return bobhash32_13bytes(key, 0xCAFEBABE) % bucket_num;
    #else
    return fasthash64_13bytes(key, FASTHASH_SEED_PRIMARY_64) % bucket_num;
    #endif
}

static __attribute__((always_inline)) inline __u32 hash_backup_64(const __u8* key, __u32 bucket_num) {
    #ifdef USE_BOBHASH
    return bobhash32_13bytes(key, 0xDEADBEEF) % bucket_num;
    #else
    return fasthash64_13bytes(key, FASTHASH_SEED_BACKUP_64) % bucket_num;
    #endif
}

static __attribute__((always_inline)) inline __u32 hash_tertiary_64(const __u8* key, __u32 bucket_num) {
    #ifdef USE_BOBHASH
    return bobhash32_13bytes(key, 0xBABECAFE) % bucket_num;
    #else
    return fasthash64_13bytes(key, FASTHASH_SEED_TERTIARY_64) % bucket_num;
    #endif
}

static __attribute__((always_inline)) inline __u32 hash_quaternary_64(const __u8* key, __u32 bucket_num) {
    #ifdef USE_BOBHASH
    return bobhash32_13bytes(key, 0xFEEDFACE) % bucket_num;
    #else
    return fasthash64_13bytes(key, FASTHASH_SEED_QUATERNARY_64) % bucket_num;
    #endif
}

static __attribute__((always_inline)) inline __u32 hash_primary_test(const __u8* key, __u32 bucket_num) {
    #ifdef USE_BOBHASH
    return ((key[0] * 31) + (key[12] * 17)) % bucket_num;
    #else
    return fasthash32_13bytes(key, 0xCAFEBABE) % bucket_num;
    #endif
}

#endif 