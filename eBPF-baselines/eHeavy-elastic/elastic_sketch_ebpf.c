
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "elastic_sketch_common.h"

struct pkt_5tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
} __attribute__((packed));


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ElasticSketch);
    __uint(max_entries, 1);
} sketch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} insert_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 3);  
} debug_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

#define FASTHASH_MIX(h) ({          \
    (h) ^= (h) >> 23;               \
    (h) *= 0x2127599bf4325c37ULL;   \
    (h) ^= (h) >> 47; })

static __always_inline __u64 fasthash64(const __u8 *buf, __u32 len, __u64 seed) {
    const __u64 m = 0x880355f21e6d1965ULL;
    __u64 h = seed ^ (len * m);
    __u64 v;

    
    #pragma unroll
    for (__u32 i = 0; i < (len / 8) && i < 2; i++) {
        __u32 offset = i * 8;
        if (offset + 8 <= len) {
            v = (__u64)buf[offset] |
                ((__u64)buf[offset + 1] << 8) |
                ((__u64)buf[offset + 2] << 16) |
                ((__u64)buf[offset + 3] << 24) |
                ((__u64)buf[offset + 4] << 32) |
                ((__u64)buf[offset + 5] << 40) |
                ((__u64)buf[offset + 6] << 48) |
                ((__u64)buf[offset + 7] << 56);
            h ^= FASTHASH_MIX(v);
            h *= m;
        }
    }

    
    __u32 remaining = len & 7;
    if (remaining > 0) {
        v = 0;
        __u32 start = (len / 8) * 8;
        
        #pragma unroll
        for (__u32 i = 0; i < 7; i++) {
            if (i < remaining) {
                v |= ((__u64)buf[start + i]) << (i * 8);
            }
        }
        
        h ^= FASTHASH_MIX(v);
        h *= m;
    }

    return FASTHASH_MIX(h);
}

static __always_inline __u32 fasthash32(const __u8 *buf, __u32 len, __u64 seed) {
    __u64 h = fasthash64(buf, len, seed);
    return (__u32)(h - (h >> 32));
}


static __always_inline __u32 key_to_fp(const __u8* key) {
    
    
    __u32 hash = 0x811C9DC5u; 
    
    #pragma unroll
    for (int i = 0; i < KEY_LEN; i++) {
        hash ^= key[i];
        hash *= 0x01000193u;  
    }
    
    return hash;
}


static __always_inline __u64 calculate_bucket_pos_u64(__u32 fp) {
    return (((__u64)fp * (__u64)CONSTANT_NUMBER) >> 15);
}

static __always_inline int calculate_fp_and_pos(const __u8 *key, __u32 *fp_out, int bucket_num) {
    __u32 fp = key_to_fp(key);
    *fp_out = fp;
    __u64 pos64 = calculate_bucket_pos_u64(fp);
    
    return (int)((pos64 % (__u64)bucket_num) & 0x3FF);
}





static __always_inline __u32 bucket_get_guard(struct Bucket *b) {
    return b->slots[MAX_VALID_COUNTER].value;
}

static __always_inline void bucket_set_guard(struct Bucket *b, __u32 val) {
    b->slots[MAX_VALID_COUNTER].value = val;
}

static __always_inline int JUDGE_IF_SWAP(__u32 min_val, __u32 guard_val, __u32 threshold) {
    return guard_val > (min_val * threshold);
}





static __always_inline void counter_init(struct counter *c) {
    c->fp = 0;
    c->value = 0;
}

static __always_inline void counter_set(struct counter *c, __u32 fp, __u32 val) {
    c->fp = fp;
    c->value = val;
}

static __always_inline void counter_inc(struct counter *c, __u32 f) {
    if (c->value < 0xFFFFFFFF - f) {
        c->value += f;
    } else {
        c->value = 0xFFFFFFFF;
    }
}





static __always_inline void lightpart_insert(struct Elastic_Lightpart *lp, __u32 fp, __u32 f) {
    if (!lp || lp->cell_num == 0) return;
    
    __u32 h = fasthash32((__u8*)&fp, sizeof(__u32), lp->fasthash_seed);
    __u32 pos = h % lp->cell_num;
    
    if (pos >= LIGHT_PART_CELLS) return;
    
    __u32 val = (__u32)lp->cells[pos] + f;
    lp->cells[pos] = (__u8)(val > 255 ? 255 : val);
    
    static __u32 light_sample_count = 0;
    if (light_sample_count < 1) {
        __u32 debug_key = 2;
        bpf_map_update_elem(&debug_map, &debug_key, &pos, BPF_ANY);
        light_sample_count++;
    }
}

static __always_inline void lightpart_swap_insert(struct Elastic_Lightpart *lp, __u32 fp, __u32 v) {
    if (!lp || lp->cell_num == 0) return;
    
    if (v > 255) v = 255;
    
    __u32 h = fasthash32((__u8*)&fp, sizeof(__u32), lp->fasthash_seed);
    __u32 pos = h % lp->cell_num;
    
    if (pos >= LIGHT_PART_CELLS) return;
    
    if (lp->cells[pos] < (__u8)v) {
        lp->cells[pos] = (__u8)v;
    }
}





static __always_inline int heavypart_insert(
    struct Elastic_Heavypart *hp,
    struct Elastic_Lightpart *lp,
    const __u8* key,
    __u32 f,
    __u32 threshold) {
    
    if (!hp || !key) return -1;
    
    __u32 fp;
    int pos = calculate_fp_and_pos(key, &fp, hp->bucket_num);
    
    static __u32 bucket_sample_count = 0;
    if (bucket_sample_count < 1) {
        __u32 debug_key = 1;
        __u32 debug_pos = (__u32)pos;
        bpf_map_update_elem(&debug_map, &debug_key, &debug_pos, BPF_ANY);
        bucket_sample_count++;
    }
    
    if (pos < 0 || pos >= MAX_BUCKETS) return -1;
    
    __u32 pos_u = (__u32)pos;
    if (pos_u >= MAX_BUCKETS) return -1;
    
    struct Bucket *bucket = &hp->buckets[pos_u];
    
    
    #pragma unroll
    for (int i = 0; i < MAX_VALID_COUNTER; i++) {
        struct counter *c = &bucket->slots[i];
        if (c->fp == fp) {
            counter_inc(c, f);
            return 0;  
        }
    }
    
    
    int empty_idx = -1;
    int min_idx = 0;
    __u32 min_val = 0xFFFFFFFF;
    
    #pragma unroll
    for (int i = 0; i < MAX_VALID_COUNTER; i++) {
        struct counter *c = &bucket->slots[i];
        __u32 val = GetCounterVal(c->value);
        
        if (c->value == 0 && empty_idx == -1) {
            empty_idx = i;
        }
        
        if (val < min_val) {
            min_val = val;
            min_idx = i;
        }
    }
    
    
    if (empty_idx >= 0) {
        counter_set(&bucket->slots[empty_idx], fp, f);
        return 0;  
    }
    
    
    __u32 guard_val = bucket_get_guard(bucket);
    guard_val = UPDATE_GUARD_VAL(guard_val);
    
    if (!JUDGE_IF_SWAP(min_val, guard_val, threshold)) {
        bucket_set_guard(bucket, guard_val);
        
        if (lp) {
            lightpart_insert(lp, fp, 1);
        }
        return 2;
    }
    
    
    __u32 victim_fp = bucket->slots[min_idx].fp;
    __u32 victim_val = bucket->slots[min_idx].value;
    
    hp->cnt++;  
    
    bucket_set_guard(bucket, 0);
    
    
    bucket->slots[min_idx].fp = fp;
    bucket->slots[min_idx].value = (0x80000000u | (f & 0x7FFFFFFFu));
    
    
    if (lp) {
        if (HIGHEST_BIT_IS_1(victim_val)) {
            
            lightpart_insert(lp, victim_fp, GetCounterVal(victim_val));
        } else {
            
            lightpart_swap_insert(lp, victim_fp, victim_val);
        }
    }
    
    return 1;  
}





static __always_inline void elastic_sketch_init(
    struct ElasticSketch *sk,
    int bucket_num,
    int cell_num,
    int threshold) {
    
    sk->hp.bucket_num = bucket_num;
    sk->hp.cnt = 0;
    sk->hp.cnt_all = 0;
    
    sk->lp.cell_num = cell_num;
    sk->lp.fasthash_seed = DEFAULT_FASTHASH_SEED;
    
    sk->threshold = threshold;
    
    
    #pragma unroll
    for (int i = 0; i < MAX_BUCKETS; i++) {
        #pragma unroll
        for (int j = 0; j < COUNTER_PER_BUCKET; j++) {
            counter_init(&sk->hp.buckets[i].slots[j]);
        }
    }
    
    
    #pragma unroll
    for (int i = 0; i < LIGHT_PART_CELLS; i++) {
        sk->lp.cells[i] = 0;
    }
}

static __always_inline void elastic_sketch_insert(
    struct ElasticSketch *sk,
    const __u8* key,
    __u32 f) {
    
    if (!sk || !key) return;
    
    sk->hp.cnt_all++;  
    
    int result = heavypart_insert(&sk->hp, &sk->lp, key, f, sk->threshold);
    
    
    
    
    
    
}





static __always_inline int parse_packet(struct xdp_md *ctx, struct pkt_5tuple *tuple) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr {
        unsigned char h_dest[6];
        unsigned char h_source[6];
        __be16 h_proto;
    } *eth;
    
    eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return -1;

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
    if ((void *)(ip + 1) > data_end) return -1;

    tuple->src_ip = ip->saddr;
    tuple->dst_ip = ip->daddr;
    tuple->proto = ip->protocol;

    if (ip->protocol == 6) {  
        struct tcphdr { __be16 source; __be16 dest; } *tcp;
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return -1;
        tuple->src_port = tcp->source;
        tuple->dst_port = tcp->dest;
    } else if (ip->protocol == 17) {  
        struct udphdr { __be16 source; __be16 dest; } *udp;
        udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) return -1;
        tuple->src_port = udp->source;
        tuple->dst_port = udp->dest;
    } else {
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    
    return 0;
}

static __always_inline void tuple_to_key(struct pkt_5tuple *tuple, __u8 *key) {
    __u32 src_ip = bpf_ntohl(tuple->src_ip);
    __u32 dst_ip = bpf_ntohl(tuple->dst_ip);
    __u16 src_port = bpf_ntohs(tuple->src_port);
    __u16 dst_port = bpf_ntohs(tuple->dst_port);
    
    key[0] = (src_ip >> 24) & 0xFF;
    key[1] = (src_ip >> 16) & 0xFF;
    key[2] = (src_ip >> 8) & 0xFF;
    key[3] = src_ip & 0xFF;
    
    key[4] = (dst_ip >> 24) & 0xFF;
    key[5] = (dst_ip >> 16) & 0xFF;
    key[6] = (dst_ip >> 8) & 0xFF;
    key[7] = dst_ip & 0xFF;
    
    key[8] = (src_port >> 8) & 0xFF;
    key[9] = src_port & 0xFF;
    
    key[10] = (dst_port >> 8) & 0xFF;
    key[11] = dst_port & 0xFF;
    
    key[12] = tuple->proto;
}





SEC("xdp")
int xdp_collect_elastic(struct xdp_md *ctx) {
    
    __u32 sig_key = 0;
    __u32 signature = 0xFA57FA57;
    bpf_map_update_elem(&debug_map, &sig_key, &signature, BPF_ANY);
    
    struct pkt_5tuple tuple = {};
    
    if (parse_packet(ctx, &tuple) < 0)
        return XDP_PASS;

    __u32 sketch_key = 0;
    struct ElasticSketch *sk = bpf_map_lookup_elem(&sketch_map, &sketch_key);
    if (!sk) {
        return XDP_PASS;
    }

    __u8 key[KEY_LEN];
    tuple_to_key(&tuple, key);
    
    elastic_sketch_insert(sk, key, 1);

    __u32 counter_key = 0;
    __u64 *counter = bpf_map_lookup_elem(&insert_counter, &counter_key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }

    return XDP_PASS;
}