#ifndef __TWOFA_EPOCH_COMMON_H
#define __TWOFA_EPOCH_COMMON_H

#define MAX_BUCKETS 16384
#define COUNTER_PER_BUCKET 8
#define MAX_VALID_COUNTER 7  
#define KEY_LEN 13


#define EPOCH_DURATION_SECONDS 1       

#define EPOCH_UPDATE_INTERVAL_NS 1000000000ULL  


#define F_MAX   1000                   
#define F_MIN   10                      

#define T1      10                      // set: Zone 1 ends at 10 epochs
#define F1      800                     // Factor at T1 = 80%

#define T2      60                      // set: Zone 2 ends at 60 epochs
#define F2      500                     // Factor at T2 = 50%

#define T3      300                     // set: Zone 3 ends at 300 epochs
#define F3      260                     // Factor at T3 = 26%

#define T4      3600                    // set: Zone 4 ends at 3600 epochs (1 hour)
#define F4      F_MIN                   // Factor at T4 = minimum

// DERIVED SLOPES (computed from breakpoints for documentation)
// S_i = (F_{i-1} - F_i) / (T_i - T_{i-1})
// S1 = (F_MAX - F1) / T1         = (1000 - 800) / 10  = 20
// S2 = (F1 - F2) / (T2 - T1)     = (800 - 500) / 50   = 6
// S3 = (F2 - F3) / (T3 - T2)     = (500 - 260) / 240  = 1
// S4 = (F3 - F4) / (T4 - T3)     = (260 - 10) / 3300  ≈ 0.076 (use integer math)

#define RECENCY_FACTOR_MIN F_MIN

struct counter {
    __u32 fp;                    
    __u32 value;                 
    __u32 last_update_epoch;   
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
};

#define CONSTANT_NUMBER 2654435761u
#define ANOTHER_BIG_PRIME_NUMBER 3344921057u

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define FORCE_INLINE inline __attribute__((__always_inline__))
#define UPDATE_GUARD_VAL(guard_val) ((guard_val) + 1)
#define JUDGE_IF_SWAP(min_val, guard_val) ((guard_val) > (min_val))

#endif 