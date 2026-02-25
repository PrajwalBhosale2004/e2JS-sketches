#ifndef __TWOFA_CORRELATIONS_COMMON_H
#define __TWOFA_CORRELATIONS_COMMON_H

#define MAX_BUCKETS 16384
#define COUNTER_PER_BUCKET 8
#define MAX_VALID_COUNTER 7  
#define KEY_LEN 13

#define CONSTANT_NUMBER 2654435761u
#define ANOTHER_BIG_PRIME_NUMBER 3344921057u

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define FORCE_INLINE inline __attribute__((__always_inline__))

#define UPDATE_GUARD_VAL(guard_val) ((guard_val) + 1)
#define JUDGE_IF_SWAP(min_val, guard_val) ((guard_val) > (min_val))


struct counter {
    __u32 fp;       
    __u32 value;                        // packet count
    __u32 persistence;                  // window count (persistence)
    __u32 last_arrived_packet_number;   // for window tracking
    __u64 flow_size;                    // total bytes of the flow

    __u32 first_seq;                    // sequence number of first packet
    __u32 last_seq;                     // sequence number of last packet

    __u32 burst_start_seq;              // burst start sequence number
    __u32 burst_end_seq;                // burst end sequence number
    __u32 curr_burst_size;              // current burst size in bytes
    __u32 burst_gap_sum;                // sum of gaps between bursts
    __u32 n_bursts;                     // number of bursts detected
    __u32 burst_rates_sum;              // sum of burst rates
};

struct Bucket {
    struct counter slots[COUNTER_PER_BUCKET];
};

struct Elastic_2FASketch_Heavypart {
    struct Bucket buckets[MAX_BUCKETS];
    __u32 bucket_num;
    __u32 cnt;      
    __u32 cnt_all;  
};

struct Elastic_2FASketch {
    struct Elastic_2FASketch_Heavypart hp;
    __u32 thres_set;
    __u64 packets_per_window; 
    __u64 total_packets;
    __u32 burst_duration;               
};

#endif 