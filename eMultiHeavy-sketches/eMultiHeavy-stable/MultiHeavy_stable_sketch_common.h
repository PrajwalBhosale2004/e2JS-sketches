#ifndef __MultiHeavy_STABLE_SKETCH_COMMON_H
#define __MultiHeavy_STABLE_SKETCH_COMMON_H

#define LGN 13  
#define MAX_DEPTH 10
#define MAX_WIDTH 1024
#define KEY_LEN 13

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define FORCE_INLINE inline __attribute__((__always_inline__))

struct MultiHeavySBucket {
    int count;              
    int stablecount;        
    unsigned char key[LGN]; 
    __u32 last_arrived_packet_number;      
    __u32 byte_counter;
    int replacement_bytes;
    int burst_start_seq_num;
    int burst_end_seq_num;
    __u32 curr_burst_size;
    __u32 burst_gap_sum;
    int n_bursts;
    __u32 burst_rates_sum;
    int first_inserted_packet_number;
    int burst_calculated;
};

struct MultiHeavyStableSketch {
    __u64 sum;                     
    __s32 depth;                                
    __s32 width;                                
    __s32 lgn;                                  
    __u64 hash_seeds[MAX_DEPTH];             
    __u64 scale_seeds[MAX_DEPTH];          
    __u64 hardner_seeds[MAX_DEPTH];             
    __u64 packets_per_window;       
    struct MultiHeavySBucket buckets[MAX_DEPTH][MAX_WIDTH]; 
    int burst_duration;
};

struct pkt_5tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
} __attribute__((packed));

#endif