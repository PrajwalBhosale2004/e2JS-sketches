#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "wavingsketch_parameters.h"
#define HASH_SEED 1324534127

#ifndef ETH_P_IP
#define ETH_P_IP 2048
#endif

typedef __s32 count_type;


struct xdp_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
};


struct ws_node {
    __u8 key[KEY_SIZE];
    count_type C;
};


struct ws_bucket {
    count_type incast;
    struct ws_node cells[CELL_NUM];
};


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xdp_stats));
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct ws_bucket));
    __uint(max_entries, BUCKET_NUM);
} wavingsketch_map SEC(".maps");


static __always_inline __u32 murmur3_32(const __u8 *key, __u32 len, __u32 seed)
{
    const __u32 c1 = 0xcc9e2d51;
    const __u32 c2 = 0x1b873593;
    const __u32 r1 = 15;
    const __u32 r2 = 13;
    const __u32 m = 5;
    const __u32 n = 0xe6546b64;

    __u32 hash = seed;
    const __u32 nblocks = len / 4;

    
    #pragma unroll
    for (__u32 i = 0; i < 3 && i < nblocks; i++) {
        __u32 k = 0;
        #pragma unroll
        for (int j = 0; j < 4; j++) {
            k |= ((__u32)key[i * 4 + j]) << (j * 8);
        }

        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        hash ^= k;
        hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
    }

    
    __u32 k1 = 0;
    __u32 remaining = len & 3;
    __u32 offset = nblocks * 4;

    if (remaining >= 1) k1 ^= key[offset];
    if (remaining >= 2) k1 ^= ((__u32)key[offset + 1]) << 8;
    if (remaining >= 3) k1 ^= ((__u32)key[offset + 2]) << 16;

    if (remaining > 0) {
        k1 *= c1;
        k1 = (k1 << r1) | (k1 >> (32 - r1));
        k1 *= c2;
        hash ^= k1;
    }

    
    hash ^= len;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    return hash;
}


static __always_inline __u32 abs_count(count_type val)
{
    return (val < 0) ? -val : val;
}


static __always_inline int memcmp_inline(const __u8 *a, const __u8 *b, __u32 size)
{
    #pragma unroll
    for (__u32 i = 0; i < KEY_SIZE && i < size; i++) {
        if (a[i] != b[i])
            return 1;
    }
    return 0;
}


static __always_inline void memcpy_inline(__u8 *dst, const __u8 *src, __u32 size)
{
    #pragma unroll
    for (__u32 i = 0; i < KEY_SIZE && i < size; i++) {
        dst[i] = src[i];
    }
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


static __always_inline void wavingsketch_insert(struct ws_bucket *bucket, const __u8 *key)
{
    __u32 hashValue = murmur3_32(key, KEY_SIZE, HASH_SEED);
    __u32 choice = hashValue & 1;
    __s32 count_delta = (choice == 0) ? 1 : -1;

    __u32 min_num = 0xFFFFFFFF;
    __u32 min_pos = 0;

    
    #pragma unroll
    for (__u32 i = 0; i < CELL_NUM; i++) {
        
        if (bucket->cells[i].C == 0) {
            memcpy_inline(bucket->cells[i].key, key, KEY_SIZE);
            bucket->cells[i].C = -1;
            return;
        }

        
        if (memcmp_inline(key, bucket->cells[i].key, KEY_SIZE) == 0) {
            if (bucket->cells[i].C < 0) {
                bucket->cells[i].C--;
            } else {
                bucket->cells[i].C++;
                bucket->incast += count_delta;
            }
            return;
        }

        
        __u32 counter_val = abs_count(bucket->cells[i].C);
        if (counter_val < min_num) {
            min_num = counter_val;
            min_pos = i;
        }
    }

    
    if ((bucket->incast * count_delta) >= (__s32)min_num) {
        if (bucket->cells[min_pos].C < 0) {
            __u32 old_hashValue = murmur3_32(bucket->cells[min_pos].key, KEY_SIZE, HASH_SEED);
            __u32 min_choice = old_hashValue & 1;
            __s32 min_count_delta = (min_choice == 0) ? 1 : -1;
            bucket->incast -= min_count_delta * bucket->cells[min_pos].C;
        }
        memcpy_inline(bucket->cells[min_pos].key, key, KEY_SIZE);
        bucket->cells[min_pos].C = min_num + 1;
    }
    bucket->incast += count_delta;
}

SEC("xdp")
int wavingsketch_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    
    __u32 stats_key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &stats_key);
    if (stats) {
        __u64 bytes = data_end - data;
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }

    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    
    __u8 key[KEY_SIZE] = {0};
    __u32 src_ip = bpf_ntohl(iph->saddr);
    __u32 dst_ip = bpf_ntohl(iph->daddr);

    key[0] = (src_ip >> 24) & 0xFF;
    key[1] = (src_ip >> 16) & 0xFF;
    key[2] = (src_ip >> 8) & 0xFF;
    key[3] = src_ip & 0xFF;

    key[4] = (dst_ip >> 24) & 0xFF;
    key[5] = (dst_ip >> 16) & 0xFF;
    key[6] = (dst_ip >> 8) & 0xFF;
    key[7] = dst_ip & 0xFF;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udph->source);
        dst_port = bpf_ntohs(udph->dest);
    }

    key[8] = (src_port >> 8) & 0xFF;
    key[9] = src_port & 0xFF;
    key[10] = (dst_port >> 8) & 0xFF;
    key[11] = dst_port & 0xFF;
    key[12] = iph->protocol;

    
    __u32 hashValue = murmur3_32(key, KEY_SIZE, HASH_SEED);
    __u32 bucket_idx = (hashValue >> 1) % BUCKET_NUM;

    
    struct ws_bucket *bucket = bpf_map_lookup_elem(&wavingsketch_map, &bucket_idx);
    if (!bucket)
        return XDP_PASS;

    
    wavingsketch_insert(bucket, key);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";