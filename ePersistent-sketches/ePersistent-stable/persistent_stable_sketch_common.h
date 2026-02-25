#ifndef __PERSISTENT_STABLE_SKETCH_COMMON_H
#define __PERSISTENT_STABLE_SKETCH_COMMON_H

#define LGN 13  
#define MAX_DEPTH 22
#define MAX_WIDTH 1024
#define KEY_LEN 13

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define FORCE_INLINE inline __attribute__((__always_inline__))

struct PersistentSBucket {
    int count;              // persistence count
    int stablecount;        
    unsigned char key[LGN]; 
    __u32 last_arrived_packet_number;      // sequence num of last packet inserted in this bkt
};

struct PersistentStableSketch {
    __u64 sum;                     //total packets encountered 
    __s32 depth;                                
    __s32 width;                                
    __s32 lgn;                                  // key length
    __u64 hash_seeds[MAX_DEPTH];             
    __u64 scale_seeds[MAX_DEPTH];          
    __u64 hardner_seeds[MAX_DEPTH];            
    __u64 packets_per_window;       //counting this in userspace after building ground truth, so that i can use it to track windows in ebpf
    struct PersistentSBucket buckets[MAX_DEPTH][MAX_WIDTH]; // bkt array
};

struct pkt_5tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
} __attribute__((packed));

#endif