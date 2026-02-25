#ifndef __FOURFA_SKETCH_COMMON_H
#define __FOURFA_SKETCH_COMMON_H

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
    __u32 value;    
};

struct Bucket {
    struct counter slots[COUNTER_PER_BUCKET];
};

struct Elastic_4FASketch_Heavypart {
    struct Bucket buckets[MAX_BUCKETS];
    __u32 bucket_num;
    __u32 cnt;       // threshold exceedances count
    __u32 cnt_all;   // total evictions count
};

struct Elastic_4FASketch {
    struct Elastic_4FASketch_Heavypart hp;
    __u32 thres_set;  
};

#endif // __FOURFA_SKETCH_COMMON_H