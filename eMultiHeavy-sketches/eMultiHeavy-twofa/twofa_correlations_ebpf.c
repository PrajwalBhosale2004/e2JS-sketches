#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "twofa_correlations_common.h"
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
    __type(value, struct Elastic_2FASketch);
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
    c->persistence = 0;
    c->last_arrived_packet_number = 0;
    c->flow_size = 0;
    // Window-based duration
    c->first_seq = 0;
    c->last_seq = 0;
    // Burstiness
    c->burst_start_seq = 0;
    c->burst_end_seq = 0;
    c->curr_burst_size = 0;
    c->burst_gap_sum = 0;
    c->n_bursts = 0;
    c->burst_rates_sum = 0;
}

static __always_inline void counter_set(struct counter *c, __u32 fp, __u32 val, __u64 pkt_size, __u32 current_seq) {
    c->fp = fp;
    c->value = val;
    c->persistence = 0;
    c->last_arrived_packet_number = 0;
    c->flow_size = pkt_size;
    // Window-based duration
    c->first_seq = current_seq;
    c->last_seq = current_seq;
    // Burstiness - start first burst
    c->burst_start_seq = current_seq;
    c->burst_end_seq = current_seq;
    c->curr_burst_size = pkt_size;
    c->burst_gap_sum = 0;
    c->n_bursts = 0;
    c->burst_rates_sum = 0;
}

static __always_inline void counter_set_with_persistence(
    struct counter *c, __u32 fp, __u32 val, __u64 current_seq, __u64 pkt_size) {
    c->fp = fp;
    c->value = val;
    c->persistence = 1;  
    c->last_arrived_packet_number = current_seq;
    c->flow_size = pkt_size;
    c->first_seq = (__u32)current_seq;
    c->last_seq = (__u32)current_seq;
    c->burst_start_seq = (__u32)current_seq;
    c->burst_end_seq = (__u32)current_seq;
    c->curr_burst_size = pkt_size;
    c->burst_gap_sum = 0;
    c->n_bursts = 0;
    c->burst_rates_sum = 0;
}

static __always_inline void counter_inc(struct counter *c, __u32 f, __u64 pkt_size, __u32 current_seq) {
    if (c->value < 0xFFFFFFFF - f) {
        c->value += f;
    } else {
        c->value = 0xFFFFFFFF;
    }
    c->flow_size += pkt_size;
    c->last_seq = current_seq;  

static __always_inline int
different_window_condition(struct counter *c, 
                          __u64 current_packet_number, 
                          __u64 packets_per_window)
{
    if (c->last_arrived_packet_number == 0)
        return 1;  
    
    __u64 last_window = c->last_arrived_packet_number / packets_per_window;
    __u64 current_window = current_packet_number / packets_per_window;
    
    return (last_window != current_window) ? 1 : 0;
}

static __always_inline void counter_inc_with_persistence(
    struct counter *c, __u32 f, __u64 current_seq, __u64 packets_per_window, __u64 pkt_size, __u32 burst_duration) {
    if (c->value < 0xFFFFFFFF - f) {
        c->value += f;
    } else {
        c->value = 0xFFFFFFFF;
    }
    c->flow_size += pkt_size;
    c->last_seq = (__u32)current_seq;  
    
    // Burstiness detection 
    __u32 gap = (__u32)current_seq - c->burst_end_seq;
    if (gap > burst_duration) {
        // End current burst and calculate burst rate
        __u32 burst_duration_pkts = c->burst_end_seq - c->burst_start_seq;
        if (burst_duration_pkts > 0) {
            __u32 burst_rate = c->curr_burst_size / burst_duration_pkts;
            c->burst_rates_sum += burst_rate;
        }
        c->n_bursts++;
        c->burst_gap_sum += gap;
        
        // Start new burst
        c->burst_start_seq = (__u32)current_seq;
        c->burst_end_seq = (__u32)current_seq;
        c->curr_burst_size = pkt_size;
    } else {
        // Continue current burst
        c->burst_end_seq = (__u32)current_seq;
        c->curr_burst_size += pkt_size;
    }
    
    // Persistence tracking 
    if (different_window_condition(c, current_seq, packets_per_window)) {
        if (c->persistence < 0xFFFFFFFF) {
            c->persistence++;
        }
        c->last_arrived_packet_number = current_seq;
    }
}


static __always_inline void Bucket_init(struct Bucket *b) {
    #pragma unroll
    for (int i = 0; i < COUNTER_PER_BUCKET; i++) {
        counter_init(&b->slots[i]);
    }
}


static __always_inline void Elastic_2FASketch_Heavypart_init(
    struct Elastic_2FASketch_Heavypart *hp, int bucket_num) {
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

static __always_inline int Elastic_2FASketch_Heavypart_quickinsert(
    struct Elastic_2FASketch_Heavypart *hp,
    const __u8* key,
    __u32 f,
    __u32 thres_set,
    __u64 current_seq,           
    __u64 packets_per_window,
    __u64 pkt_size,
    __u32 burst_duration) {  
    
    if (!hp || !key) return -1;
    
    __u32 fp = key_to_fp(key);
    
    __u32 pos;
    if (thres_set == 0) {
        pos = hash_backup_64(key, hp->bucket_num);
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
            counter_inc_with_persistence(c, f, current_seq, packets_per_window, pkt_size, burst_duration);
            return 0;
        }
        
        if (c->value == 0 && empty_idx == -1) {
            empty_idx = i;
        }
        
        if (c->value > 0 && c->value < min_val) {
            min_val = c->value;
            min_idx = i;
        }
    }
    
    if (empty_idx >= 0) {
        counter_set_with_persistence(&bucket->slots[empty_idx], fp, f, current_seq, pkt_size);
        return 0;
    }
    
    if (thres_set > 0 && min_val >= thres_set) {
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
    counter_set_with_persistence(&bucket->slots[min_idx], fp, guard_val, current_seq, pkt_size);
    
    return 1;
}


static __always_inline void Elastic_2FASketch_init(
    struct Elastic_2FASketch *sk, int bucket_num, int thres_set) {
    Elastic_2FASketch_Heavypart_init(&sk->hp, bucket_num);
    sk->thres_set = thres_set;
}

static __always_inline void Elastic_2FASketch_insert(
    struct Elastic_2FASketch *sk, const __u8* key, __u32 f, __u64 current_seq, __u64 pkt_size) {
    if (!sk || !key) return;
    
    int res = Elastic_2FASketch_Heavypart_quickinsert(&sk->hp, key, f, sk->thres_set, 
                                                      current_seq, sk->packets_per_window, pkt_size, sk->burst_duration);
    
    if (res == (__s32)sk->thres_set) {
        Elastic_2FASketch_Heavypart_quickinsert(&sk->hp, key, f, 0, 
                                                current_seq, sk->packets_per_window, pkt_size, sk->burst_duration);
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
int xdp_collect_2fa(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 pkt_size = (__u64)(data_end - data);
    
    struct pkt_5tuple tuple = {};
    
    if (parse_packet(ctx, &tuple) < 0)
        return XDP_DROP;

    __u32 sketch_key = 0;
    struct Elastic_2FASketch *sk = bpf_map_lookup_elem(&sketch_map, &sketch_key);
    if (!sk) {
        return XDP_DROP;
    }

    __u8 key[KEY_LEN];
    tuple_to_key(&tuple, key);
    
    __u32 counter_key = 0;
    __u64 *counter = bpf_map_lookup_elem(&insert_counter, &counter_key);
    __u64 current_seq = 0;
    if (counter) {
        current_seq = *counter;
        __sync_fetch_and_add(counter, 1);
    }
    
    Elastic_2FASketch_insert(sk, key, 1, current_seq, pkt_size);

    return XDP_PASS;  
}