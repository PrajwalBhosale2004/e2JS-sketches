#ifndef __STABLE_SKETCH_COMMON_H
#define __STABLE_SKETCH_COMMON_H

#define LGN 13 
#define MAX_DEPTH 22
#define MAX_WIDTH 1024
#define KEY_LEN 13

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define FORCE_INLINE inline __attribute__((__always_inline__))

struct SBucket {
    int count;
    int stablecount;
    unsigned char key[LGN];
};

struct StableSketch {
    __u64 sum;
    __s32 depth;
    __s32 width;
    __s32 lgn;
    __u64 hash_seeds[MAX_DEPTH];
    __u64 scale_seeds[MAX_DEPTH];
    __u64 hardner_seeds[MAX_DEPTH];
    struct SBucket buckets[MAX_DEPTH][MAX_WIDTH];
};

struct pkt_5tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
} __attribute__((packed));

#endif