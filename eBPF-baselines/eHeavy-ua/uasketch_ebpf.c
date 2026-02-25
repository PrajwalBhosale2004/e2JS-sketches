#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "uasketch_parameters.h"
#define HASH_SEED 1324534127
#define MAX_CPUS 128

#ifndef ETH_P_IP
#define ETH_P_IP 2048
#endif


struct ua_bucket {
    __u8 key[KEY_SIZE];
    __u32 C;           
    __u8 u_max;        
    __u8 u_cur;        
    __u8 padding[2];   
};


struct xdp_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ua_bucket);
    __uint(max_entries, ROW_NUM * COL_NUM);
} uasketch_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct xdp_stats);
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} rng_state_map SEC(".maps");


static __always_inline __u32 murmur3_32(const __u8 *key, __u32 len, __u32 seed) {
    __u32 h = seed;
    __u32 k;
    
    
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (i * 4 + 3 < len) {
            k = (__u32)key[i*4] | 
                ((__u32)key[i*4+1] << 8) | 
                ((__u32)key[i*4+2] << 16) | 
                ((__u32)key[i*4+3] << 24);
            
            k *= 0xcc9e2d51;
            k = (k << 15) | (k >> 17);
            k *= 0x1b873593;
            
            h ^= k;
            h = (h << 13) | (h >> 19);
            h = h * 5 + 0xe6546b64;
        }
    }
    
    
    k = 0;
    k ^= key[12];
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
    
    
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    
    return h;
}


static __always_inline __u32 get_random(__u32 *state) {
    *state = (*state * 1103515245 + 12345) & 0x7fffffff;
    return *state;
}


static __always_inline int key_equal(const __u8 *k1, const __u8 *k2) {
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        if (k1[i] != k2[i])
            return 0;
    }
    return 1;
}


static __always_inline int key_is_empty(const __u8 *k) {
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        if (k[i] != 0)
            return 0;
    }
    return 1;
}


static __always_inline void key_copy(__u8 *dst, const __u8 *src) {
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        dst[i] = src[i];
    }
}


static __always_inline int extract_key(void *data, void *data_end, __u8 *key) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;
    
    
    __u32 saddr = bpf_ntohl(iph->saddr);
    key[0] = (saddr >> 24) & 0xFF;
    key[1] = (saddr >> 16) & 0xFF;
    key[2] = (saddr >> 8) & 0xFF;
    key[3] = saddr & 0xFF;
    
    
    __u32 daddr = bpf_ntohl(iph->daddr);
    key[4] = (daddr >> 24) & 0xFF;
    key[5] = (daddr >> 16) & 0xFF;
    key[6] = (daddr >> 8) & 0xFF;
    key[7] = daddr & 0xFF;
    
    __u16 sport = 0, dport = 0;
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((void *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;
        sport = bpf_ntohs(tcph->source);
        dport = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((void *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;
        sport = bpf_ntohs(udph->source);
        dport = bpf_ntohs(udph->dest);
    }
    
    
    key[8] = (sport >> 8) & 0xFF;
    key[9] = sport & 0xFF;
    
    
    key[10] = (dport >> 8) & 0xFF;
    key[11] = dport & 0xFF;
    
    
    key[12] = iph->protocol;
    
    return 0;
}


static __always_inline void uasketch_insert(__u8 *key, __u32 *rng_state) {
    #pragma unroll
    for (__u32 row_idx = 0; row_idx < ROW_NUM; row_idx++) {
        
        __u32 hash_seed = HASH_SEED + 6156137 * row_idx;
        __u32 hash_val = murmur3_32(key, KEY_SIZE, hash_seed);
        __u32 col_idx = hash_val % COL_NUM;
        
        
        __u32 map_idx = row_idx * COL_NUM + col_idx;
        
        struct ua_bucket *bucket = bpf_map_lookup_elem(&uasketch_map, &map_idx);
        if (!bucket)
            continue;
        
        
        if (bucket->C == 0) {
            key_copy(bucket->key, key);
            bucket->C = 1;
            bucket->u_max = 1;
            bucket->u_cur = 1;
        }
        
        else if (key_equal(key, bucket->key)) {
            bucket->C++;
            
            if (bucket->u_cur < 255) {  
                bucket->u_cur++;
                if (bucket->u_max < bucket->u_cur) {
                    bucket->u_max = bucket->u_cur;
                }
            }
        }
        
        else {
            bucket->u_cur = 0;
            
            
            
            __u32 rand_val = get_random(rng_state);
            
            
            __u64 denominator = (__u64)bucket->C * (__u64)bucket->u_max;
            if (denominator == 0)
                denominator = 1;
            
            
            
            __u64 threshold = 0xFFFFFFFFULL / denominator;
            
            if (rand_val < threshold) {
                key_copy(bucket->key, key);
                bucket->u_max = 1;
                bucket->u_cur = 1;
            }
        }
    }
}

SEC("xdp")
int uasketch_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    
    __u32 stats_key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &stats_key);
    if (stats) {
        __u64 bytes = data_end - data;
        stats->rx_packets++;
        stats->rx_bytes += bytes;
    }
    
    
    __u8 key[KEY_SIZE] = {0};
    if (extract_key(data, data_end, key) != 0) {
        return XDP_PASS;
    }
    
    
    __u32 rng_key = 0;
    __u32 *rng_state = bpf_map_lookup_elem(&rng_state_map, &rng_key);
    if (!rng_state) {
        return XDP_PASS;
    }
    
    
    uasketch_insert(key, rng_state);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";