#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "chainsketch_parameters.h"
#define MAX_CHAIN_LENGTH 3
#define HASH_SEED 419

#ifndef ETH_P_IP
#define ETH_P_IP 2048
#endif


struct cs_bucket {
    __u8 key[KEY_SIZE];
    __u32 counter;
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cs_bucket);
    __uint(max_entries, ROW_NUM * COL_NUM);
} chainsketch_map SEC(".maps");


struct xdp_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct xdp_stats);
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");


static __always_inline __u32 hash_key(const __u8 *key, __u32 seed)
{
    __u32 hash = 2166136261u ^ seed;
    
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        hash ^= key[i];
        hash *= 16777619u;
    }
    
    return hash;
}


static __always_inline int is_key_empty(const __u8 *key)
{
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        if (key[i] != 0)
            return 0;
    }
    return 1;
}


static __always_inline int keys_equal(const __u8 *key1, const __u8 *key2)
{
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        if (key1[i] != key2[i])
            return 0;
    }
    return 1;
}


static __always_inline void copy_key(__u8 *dst, const __u8 *src)
{
    #pragma unroll
    for (int i = 0; i < KEY_SIZE; i++) {
        dst[i] = src[i];
    }
}


static __always_inline __u32 get_random(__u32 seed)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}


static __always_inline void chainsketch_insert(__u8 *key)
{
    __u32 min_counter = 0xFFFFFFFF;
    __u32 min_row_idx = 0;
    __u32 min_col_idx = 0;
    
    
    #pragma unroll
    for (__u32 row = 0; row < ROW_NUM; row++) {
        __u32 hash_val = hash_key(key, HASH_SEED + 6156137 * row);
        __u32 col = hash_val % COL_NUM;
        __u32 bucket_idx = row * COL_NUM + col;
        
        struct cs_bucket *bucket = bpf_map_lookup_elem(&chainsketch_map, &bucket_idx);
        if (!bucket)
            continue;
        
        
        if (bucket->counter == 0) {
            copy_key(bucket->key, key);
            bucket->counter = 1;
            return;
        }
        
        
        if (keys_equal(key, bucket->key)) {
            bucket->counter++;
            return;
        }
        
        
        if (bucket->counter < min_counter) {
            min_row_idx = row;
            min_col_idx = col;
            min_counter = bucket->counter;
        }
    }
    
    
    __u32 rand_seed = hash_key(key, bpf_ktime_get_ns());
    __u32 random_val = get_random(rand_seed);
    
    
    
    __u64 threshold = (__u64)(min_counter + 1);
    __u64 rand_check = (__u64)random_val;
    
    if (rand_check * threshold <= 0xFFFFFFFFULL) {
        __u32 min_bucket_idx = min_row_idx * COL_NUM + min_col_idx;
        struct cs_bucket *min_bucket = bpf_map_lookup_elem(&chainsketch_map, &min_bucket_idx);
        if (!min_bucket)
            return;
        
        
        if (min_counter >= 512) {
            __u32 chain_hash = hash_key(key, HASH_SEED + 21151121);
            __u32 p2 = (min_col_idx + chain_hash) % COL_NUM;
            
            
            #pragma unroll
            for (__u32 l = 2; l <= MAX_CHAIN_LENGTH; l++) {
                __u32 chain_bucket_idx = min_row_idx * COL_NUM + p2;
                struct cs_bucket *chain_bucket = bpf_map_lookup_elem(&chainsketch_map, &chain_bucket_idx);
                if (!chain_bucket)
                    break;
                
                
                if (chain_bucket->counter < min_counter) {
                    __u32 move_rand = get_random(rand_seed + l);
                    
                    
                    if (move_rand % (min_counter + chain_bucket->counter) < min_counter) {
                        copy_key(chain_bucket->key, min_bucket->key);
                        chain_bucket->counter = min_counter;
                        break;
                    }
                }
                
                p2 = (p2 + chain_hash) % COL_NUM;
            }
        }
        
        
        copy_key(min_bucket->key, key);
        min_bucket->counter++;
    }
}


static __always_inline int extract_flow_key(struct xdp_md *ctx, __u8 *flow_key)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;
    
    
    __u32 src_ip = bpf_ntohl(iph->saddr);
    flow_key[0] = (src_ip >> 24) & 0xFF;
    flow_key[1] = (src_ip >> 16) & 0xFF;
    flow_key[2] = (src_ip >> 8) & 0xFF;
    flow_key[3] = src_ip & 0xFF;
    
    
    __u32 dst_ip = bpf_ntohl(iph->daddr);
    flow_key[4] = (dst_ip >> 24) & 0xFF;
    flow_key[5] = (dst_ip >> 16) & 0xFF;
    flow_key[6] = (dst_ip >> 8) & 0xFF;
    flow_key[7] = dst_ip & 0xFF;
    
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return -1;
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return -1;
        src_port = bpf_ntohs(udph->source);
        dst_port = bpf_ntohs(udph->dest);
    }
    
    
    flow_key[8] = (src_port >> 8) & 0xFF;
    flow_key[9] = src_port & 0xFF;
    
    
    flow_key[10] = (dst_port >> 8) & 0xFF;
    flow_key[11] = dst_port & 0xFF;
    
    
    flow_key[12] = iph->protocol;
    
    return 0;
}

SEC("xdp")
int chainsketch_xdp(struct xdp_md *ctx)
{
    __u8 flow_key[KEY_SIZE] = {0};
    
    
    __u32 stats_key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &stats_key);
    if (stats) {
        __u64 pkt_len = (__u64)(ctx->data_end - ctx->data);
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, pkt_len);
    }
    
    
    if (extract_flow_key(ctx, flow_key) < 0)
        return XDP_PASS;
    
    
    chainsketch_insert(flow_key);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";