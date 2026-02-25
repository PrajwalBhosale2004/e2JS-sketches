#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "heavyguardian_parameters.h"
#define HK_b_INT 108  
#define HASH_SEED 0x9747b28c

#ifndef ETH_P_IP
#define ETH_P_IP 2048
#endif


struct hg_node {
    __u8 key[KEY_SIZE];
    __u32 counter;
};


struct hg_bucket {
    struct hg_node cells[CELL_NUM];
};


struct xdp_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct hg_bucket);
    __uint(max_entries, BUCKET_NUM);
} heavyguardian_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct xdp_stats);
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} random_state_map SEC(".maps");


static __always_inline __u32 murmur3_32(const __u8 *key, __u32 len, __u32 seed) {
    __u32 h = seed;
    __u32 k;
    
    
    #pragma unroll
    for (__u32 i = 0; i < 3; i++) {
        if (i * 4 + 3 < len) {
            k = (__u32)key[i * 4] |
                ((__u32)key[i * 4 + 1] << 8) |
                ((__u32)key[i * 4 + 2] << 16) |
                ((__u32)key[i * 4 + 3] << 24);
            
            k *= 0xcc9e2d51;
            k = (k << 15) | (k >> 17);
            k *= 0x1b873593;
            
            h ^= k;
            h = (h << 13) | (h >> 19);
            h = h * 5 + 0xe6546b64;
        }
    }
    
    
    k = 0;
    if (len > 12) {
        k = (__u32)key[12];
        k *= 0xcc9e2d51;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593;
        h ^= k;
    }
    
    
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    
    return h;
}


static __always_inline __u32 get_random(__u64 *state) {
    *state = *state * 1103515245ULL + 12345ULL;
    return (*state >> 16) & 0x7FFFFFFF;
}


static __always_inline __u32 compute_threshold(__u32 counter) {
    
    
    
    
    
    if (counter == 0) return 100; 
    if (counter >= 20) return 1;  
    
    __u64 numerator = 100;
    __u64 denominator = 108;
    
    #pragma unroll
    for (__u32 i = 1; i < 20; i++) {
        if (i < counter) {
            numerator *= 100;
            denominator *= 108;
            
            if (denominator > 1000000) {
                numerator /= 1000;
                denominator /= 1000;
            }
        }
    }
    
    
    if (denominator == 0) return 0;
    return (__u32)((numerator * 10000) / denominator);
}


static __always_inline int extract_flow_key(void *data, void *data_end, __u8 *key) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;
    
    
    __u32 saddr = bpf_ntohl(iph->saddr);
    __u32 daddr = bpf_ntohl(iph->daddr);
    
    key[0] = (saddr >> 24) & 0xFF;
    key[1] = (saddr >> 16) & 0xFF;
    key[2] = (saddr >> 8) & 0xFF;
    key[3] = saddr & 0xFF;
    
    key[4] = (daddr >> 24) & 0xFF;
    key[5] = (daddr >> 16) & 0xFF;
    key[6] = (daddr >> 8) & 0xFF;
    key[7] = daddr & 0xFF;
    
    __u8 protocol = iph->protocol;
    __u16 sport = 0, dport = 0;
    
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return -1;
        sport = bpf_ntohs(tcph->source);
        dport = bpf_ntohs(tcph->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return -1;
        sport = bpf_ntohs(udph->source);
        dport = bpf_ntohs(udph->dest);
    }
    
    key[8] = (sport >> 8) & 0xFF;
    key[9] = sport & 0xFF;
    key[10] = (dport >> 8) & 0xFF;
    key[11] = dport & 0xFF;
    key[12] = protocol;
    
    return 0;
}


static __always_inline int key_equal(const __u8 *k1, const __u8 *k2) {
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        if (k1[i] != k2[i])
            return 0;
    }
    return 1;
}


static __always_inline int key_is_empty(const __u8 *key) {
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        if (key[i] != 0)
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

SEC("xdp")
int heavyguardian_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    
    __u32 stats_key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &stats_key);
    if (stats) {
        __u64 bytes = data_end - data;
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
    
    
    __u8 key[KEY_SIZE];
    __builtin_memset(key, 0, KEY_SIZE);
    
    if (extract_flow_key(data, data_end, key) < 0)
        return XDP_PASS;
    
    
    __u32 hash = murmur3_32(key, KEY_SIZE, HASH_SEED);
    __u32 bucket_idx = hash % BUCKET_NUM;
    
    
    struct hg_bucket *bucket = bpf_map_lookup_elem(&heavyguardian_map, &bucket_idx);
    if (!bucket)
        return XDP_PASS;
    
    
    __u32 min_cell_idx = 0;
    __u32 min_counter = 0xFFFFFFFF;
    int found = 0;
    
    
    #pragma unroll
    for (int i = 0; i < CELL_NUM; i++) {
        
        if (bucket->cells[i].counter == 0) {
            bucket->cells[i].counter = 1;
            key_copy(bucket->cells[i].key, key);
            return XDP_PASS;
        }
        
        
        if (key_equal(key, bucket->cells[i].key)) {
            bucket->cells[i].counter++;
            found = 1;
            break;
        }
        
        
        if (bucket->cells[i].counter < min_counter) {
            min_counter = bucket->cells[i].counter;
            min_cell_idx = i;
        }
    }
    
    if (found)
        return XDP_PASS;
    
    
    __u32 rnd_key = 0;
    __u64 *rnd_state = bpf_map_lookup_elem(&random_state_map, &rnd_key);
    if (!rnd_state)
        return XDP_PASS;
    
    __u32 threshold = compute_threshold(min_counter);
    __u32 rand_val = get_random(rnd_state) % 10000;
    
    if (rand_val < threshold) {
        if (bucket->cells[min_cell_idx].counter > 1) {
            bucket->cells[min_cell_idx].counter--;
        } else {
            key_copy(bucket->cells[min_cell_idx].key, key);
            bucket->cells[min_cell_idx].counter = 1;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";