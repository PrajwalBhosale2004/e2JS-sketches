#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "fourfa_sketch_common.h"
#include "unified_hash.h"

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
    __type(value, struct Elastic_4FASketch);
    __uint(max_entries, 1);
} sketch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} insert_counter SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u32 key_to_fp(const __u8* key) {
    __u32 hash = 0x9e3779b1; 
    
    #pragma unroll
    for (int i = 0; i < KEY_LEN; i++) {
        hash ^= key[i];
        hash *= 0x85ebca77; 
        hash ^= (hash >> 13);
    }
    
    hash ^= (hash >> 16);
    hash *= 0x3243f6a9;
    hash ^= (hash >> 16);
    
    return hash;
}


static __always_inline __u32 bucket_get_guard(struct Bucket *b) {
    return b->slots[MAX_VALID_COUNTER].value;
}

static __always_inline void bucket_set_guard(struct Bucket *b, __u32 val) {
    b->slots[MAX_VALID_COUNTER].value = val;
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


static __always_inline void Bucket_init(struct Bucket *b) {
    #pragma unroll
    for (int i = 0; i < COUNTER_PER_BUCKET; i++) {
        counter_init(&b->slots[i]);
    }
}


static __always_inline void Elastic_4FASketch_Heavypart_init(
    struct Elastic_4FASketch_Heavypart *hp, int bucket_num) {
    hp->bucket_num = bucket_num;
    hp->cnt = 0;
    hp->cnt_all = 0;
    
    #pragma unroll
    for (int i = 0; i < MAX_BUCKETS; i++) {
        if (i < bucket_num) {
            Bucket_init(&hp->buckets[i]);
        }
    }
}

static __always_inline int Elastic_4FASketch_Heavypart_quickinsert(
    struct Elastic_4FASketch_Heavypart *hp,
    const __u8* key,
    __u32 f,
    __u32 thres_set) {
    
    if (!hp || !key) return -1;
    
    __u32 fp = key_to_fp(key);
    
    __u32 pos;
    if (thres_set == 0) {
        pos = hash_backup_64(key, hp->bucket_num);
    } else if (thres_set == 1) {
        pos = hash_tertiary_64(key, hp->bucket_num);
    } else if (thres_set == 2) {
        pos = hash_quaternary_64(key, hp->bucket_num);
    } else {
        pos = hash_primary_64(key, hp->bucket_num);
    }
    
    if (pos >= MAX_BUCKETS) return -1;
    
    struct Bucket *bucket = &hp->buckets[pos];
    
    int min_idx = 0;
    __u32 min_val = 0xFFFFFFFF;
    int empty_idx = -1;
    
    #pragma unroll
    for (int i = 0; i < MAX_VALID_COUNTER; i++) {
        struct counter *c = &bucket->slots[i];
        
        if (c->fp == fp) {
            counter_inc(c, f);
            return 0;
        }
        
        if (c->value == 0 && empty_idx == -1) {
            empty_idx = i;
        }
        
        if (c->value < min_val) {
            min_val = c->value;
            min_idx = i;
        }
    }
    
    if (empty_idx >= 0) {
        counter_set(&bucket->slots[empty_idx], fp, f);
        return 0;
    }
    
    // Only check threshold on primary hash (thres_set > 2)
    if (thres_set > 2 && min_val >= thres_set) {
        hp->cnt++;
        return thres_set;
    }
    
    hp->cnt_all++;
    __u32 guard_val = bucket_get_guard(bucket);
    guard_val = UPDATE_GUARD_VAL(guard_val);
    
    if (!JUDGE_IF_SWAP(min_val, guard_val)) {
        bucket_set_guard(bucket, guard_val);
        return 2;
    }
    
    bucket_set_guard(bucket, 0);
    counter_set(&bucket->slots[min_idx], fp, guard_val);
    
    return 1;
}


static __always_inline void Elastic_4FASketch_init(
    struct Elastic_4FASketch *sk, int bucket_num, int thres_set) {
    Elastic_4FASketch_Heavypart_init(&sk->hp, bucket_num);
    sk->thres_set = thres_set;
}

static __always_inline void Elastic_4FASketch_insert(
    struct Elastic_4FASketch *sk, const __u8* key, __u32 f) {
    if (!sk || !key) return;
    
    int res = Elastic_4FASketch_Heavypart_quickinsert(&sk->hp, key, f, sk->thres_set);
    
    if (res == (__s32)sk->thres_set) {
        res = Elastic_4FASketch_Heavypart_quickinsert(&sk->hp, key, f, 0);
        
        if (res != 0) {
            res = Elastic_4FASketch_Heavypart_quickinsert(&sk->hp, key, f, 1);
            
            if (res != 0) {
                Elastic_4FASketch_Heavypart_quickinsert(&sk->hp, key, f, 2);
            }
        }
    }
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
int xdp_collect_4fa(struct xdp_md *ctx) {
    struct pkt_5tuple tuple = {};
    
    if (parse_packet(ctx, &tuple) < 0)
        return XDP_DROP;

    __u32 sketch_key = 0;
    struct Elastic_4FASketch *sk = bpf_map_lookup_elem(&sketch_map, &sketch_key);
    if (!sk) {
        return XDP_DROP;
    }

    __u8 key[KEY_LEN];
    tuple_to_key(&tuple, key);
    
    Elastic_4FASketch_insert(sk, key, 1);

    __u32 counter_key = 0;
    __u64 *counter = bpf_map_lookup_elem(&insert_counter, &counter_key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }

    return XDP_DROP;
}