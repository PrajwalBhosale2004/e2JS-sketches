#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "persistent_stable_sketch_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct PersistentStableSketch);
    __uint(max_entries, 1);
} persistent_sketch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_counter SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

struct key13 {
    __u8 b[13];
};

static __always_inline __u64
MurmurHash64A_ebpf(struct key13 key, __u64 seed)
{
    const __u64 m = 0xc6a4a7935bd1e995ULL;
    const int r = 47;

    __u64 h = seed ^ (13 * m);

    #pragma clang loop unroll(full)
    for (int i = 0; i < 13; i++) {
        __u64 k = key.b[i];
        k *= m;
        k ^= k >> r;
        k *= m;
        h ^= k;
        h *= m;
    }

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
}

static __always_inline __u32
simple_rand(__u32 *seed, struct key13 key)
{
    __u32 mix = 0;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        mix ^= ((__u32)key.b[i]) << (i * 8);
    }

    *seed = (*seed * 1103515245 + 12345 + mix) & 0x7fffffff;
    return *seed;
}

static __always_inline __u32
simple_rand2(__u32 *seed, struct key13 key)
{
    __u32 mix = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        mix ^= ((__u32)key.b[i]) << (i * 8);
    }
    
    __u32 x = *seed ^ mix;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    
    *seed = x;
    return x; 
}


static __always_inline int
different_window_condition(struct PersistentSBucket *sbucket, __u64 current_packet_number, __u64 packets_per_window)
{
    if (sbucket->last_arrived_packet_number == 0)
        return 1;  //first insertion in this bkt, so allow
    if (sbucket->last_arrived_packet_number / packets_per_window != current_packet_number / packets_per_window) {
        return 1; // diff window, so allow 
    } else {
        return 0; // same window
    }
}

static __always_inline void
PersistentStableSketch_Update(struct PersistentStableSketch *pss,
                               struct key13 key,
                               __u32 val)
{
    if (!pss)
        return;
    
    __u32 keylen = (__u32)pss->lgn / 8;
    pss->sum += 1;
    
    __u32 flag = 0;
    __u64 min_count = 0x7FFFFFFF;
    __s32 min_loc = -1;
    
    static __u32 rand_seed = 12345;
    
    #pragma clang loop unroll_count(22)
    for (int i = 0; i < MAX_DEPTH; i++) {
        if (i >= pss->depth)
            break;
        
        __u64 hash_val = MurmurHash64A_ebpf(key, pss->hardner_seeds[i]);
        __u32 bucket_idx = hash_val % pss->width;
        
        if (bucket_idx >= MAX_WIDTH)
            continue;
        
        struct PersistentSBucket *sbucket = &pss->buckets[i][bucket_idx];
        
        // 1) finding empty bucket
        int is_empty = 1;
        #pragma unroll
        for (int k = 0; k < 13; k++) {
            if (sbucket->key[k] != 0) {
                is_empty = 0;
                break;
            }
        }
        
        if (is_empty && sbucket->count == 0 && different_window_condition(sbucket, pss->sum, pss->packets_per_window)) {
            #pragma unroll
            for (int k = 0; k < 13; k++) {
                sbucket->key[k] = key.b[k];
            }
            flag = 1;
            sbucket->count = 1;   // init persistence = 1
            sbucket->stablecount = sbucket->stablecount + 1;
            sbucket->last_arrived_packet_number = pss->sum;
            return;
        }

        // 2) item already in bucket
        int key_match = 1;
        #pragma unroll
        for (int k = 0; k < 13; k++) {
            if (key.b[k] != sbucket->key[k]) {
                key_match = 0;
                break;
            }
        }
        
        if (key_match) {
            // here the last_arrived_packet_number is used to check if we are in a different window
            if (different_window_condition(sbucket, pss->sum, pss->packets_per_window)) {
                flag = 1;
                sbucket->count += 1;             
                sbucket->stablecount += 1;        
                sbucket->last_arrived_packet_number = pss->sum;
            }
            // if item is already counted in this window, do nothing
            return;
        }
        
        // track minimum p_count bucket for replacement
        if (sbucket->count < min_count) {
            min_count = sbucket->count;
            min_loc = i * MAX_WIDTH + bucket_idx;
        }
    }
    
    //3)collision and no empty bucket found, so probabilistic replacement
    if (flag == 0 && min_loc >= 0) {
        __u32 row = (__u32)min_loc / MAX_WIDTH;
        __u32 col = (__u32)min_loc % MAX_WIDTH;
        if (row >= MAX_DEPTH || col >= MAX_WIDTH)
            return;
        if (row >= pss->depth || col >= pss->width)
            return;
        struct PersistentSBucket *sbucket = &pss->buckets[row][col];
        
        // as per the paper, dont replace if the min_count item is inserted in this same window
        if (!different_window_condition(sbucket, pss->sum, pss->packets_per_window)) {
            return;
        }
        
        // replacement prob. : 1 / (count * stablecount + 1)
        __u64 product = (__u64)(sbucket->stablecount) * (__u64)(sbucket->count);
        if (product >= 0xFFFFFFFF) 
            product = 0xFFFFFFFF - 1;
        __u64 denom = product + 1;
        if (denom <= 0)
            denom = 1;
        
        __u32 rand_val = simple_rand(&rand_seed, key);
        __u32 k = rand_val % denom;
        
        // prob. decay and eventual replacement
        if (k == 0) {
            sbucket->count -= 1;  
            if (sbucket->count <= 0) {  
                #pragma unroll
                for (int i = 0; i < 13; i++) {
                    sbucket->key[i] = key.b[i];
                }
                sbucket->count += 1;
                sbucket->stablecount = sbucket->stablecount - 1;
                if (sbucket->stablecount <= 0) {
                    sbucket->stablecount = 0;
                }
            }
            sbucket->status = 1;  
            sbucket->last_arrived_packet_number = pss->sum;
        }
    }
}


static __always_inline struct key13
tuple_to_key(struct pkt_5tuple *tuple)
{
    struct key13 key = {};

    __u32 src = bpf_ntohl(tuple->src_ip);
    __u32 dst = bpf_ntohl(tuple->dst_ip);
    __u16 sport = bpf_ntohs(tuple->src_port);
    __u16 dport = bpf_ntohs(tuple->dst_port);

    key.b[0] = (src >> 24) & 0xFF;
    key.b[1] = (src >> 16) & 0xFF;
    key.b[2] = (src >> 8) & 0xFF;
    key.b[3] = src & 0xFF;

    key.b[4] = (dst >> 24) & 0xFF;
    key.b[5] = (dst >> 16) & 0xFF;
    key.b[6] = (dst >> 8) & 0xFF;
    key.b[7] = dst & 0xFF;

    key.b[8]  = (sport >> 8) & 0xFF;
    key.b[9]  = sport & 0xFF;
    key.b[10] = (dport >> 8) & 0xFF;
    key.b[11] = dport & 0xFF;

    key.b[12] = tuple->proto;

    return key;
}

static int FORCE_INLINE parse_packet(struct xdp_md *ctx, struct pkt_5tuple *tuple) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr {
        unsigned char h_dest[6];
        unsigned char h_source[6];
        __be16 h_proto;
    } *eth;
    
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;
    
    struct iphdr {
        __u8 ihl:4;
        __u8 version:4;
        __u8 tos;
        __be16 tot_len;
        __be16 id;
        __be16 frag_off;
        __u8 ttl;
        __u8 protocol;
        __be16 check;
        __be32 saddr;
        __be32 daddr;
    } *ip;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    tuple->src_ip = ip->saddr;
    tuple->dst_ip = ip->daddr;
    tuple->proto = ip->protocol;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr {
            __be16 source;
            __be16 dest;
            __be32 seq;
            __be32 ack_seq;
        } *tcp;
        
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        
        tuple->src_port = tcp->source;
        tuple->dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr {
            __be16 source;
            __be16 dest;
            __be16 len;
            __be16 check;
        } *udp;
        
        udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -1;
        
        tuple->src_port = udp->source;
        tuple->dst_port = udp->dest;
    } else {
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    
    return 0;
}

SEC("xdp")
int xdp_persistent_collect(struct xdp_md *ctx) {
    struct pkt_5tuple tuple = {};
    
    if (parse_packet(ctx, &tuple) < 0)
        return XDP_PASS;
    
    struct key13 tuple_key = tuple_to_key(&tuple);
    
    __u32 key = 0;
    struct PersistentStableSketch *psk;
    
    psk = bpf_map_lookup_elem(&persistent_sketch_map, &key);
    if (!psk)
        return XDP_PASS;
    
    PersistentStableSketch_Update(psk, tuple_key, 1);
    
    __u64 *pkt_count = bpf_map_lookup_elem(&packet_counter, &key);
    if (pkt_count)
        __sync_fetch_and_add(pkt_count, 1);
    
    return XDP_PASS;
}