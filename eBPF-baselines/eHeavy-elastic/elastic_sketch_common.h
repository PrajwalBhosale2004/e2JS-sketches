#ifndef __ELASTIC_SKETCH_COMMON_H
#define __ELASTIC_SKETCH_COMMON_H

#define MAX_BUCKETS 4096
#define COUNTER_PER_BUCKET 8
#define MAX_VALID_COUNTER 7
#define KEY_LEN 13


#define LIGHT_PART_CELLS 16384  

#define CONSTANT_NUMBER 2654435761u
#define DEFAULT_FASTHASH_SEED 0xCAFEBABEULL

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define FORCE_INLINE inline __attribute__((__always_inline__))

#define HIGHEST_BIT_IS_1(v) ((v) & 0x80000000u)
#define GetCounterVal(v)    ((__u32)((v) & 0x7FFFFFFFu))
#define UPDATE_GUARD_VAL(guard_val) ((guard_val) + 1)

struct counter {
    __u32 fp;       
    __u32 value;    
};

struct Bucket {
    struct counter slots[COUNTER_PER_BUCKET];
};

struct Elastic_Heavypart {
    struct Bucket buckets[MAX_BUCKETS];
    __u32 bucket_num;
    __u32 cnt;       
    __u32 cnt_all;   
};

struct Elastic_Lightpart {
    __u8 cells[LIGHT_PART_CELLS];  
    __u32 cell_num;
    __u64 fasthash_seed;
};

struct ElasticSketch {
    struct Elastic_Heavypart hp;
    struct Elastic_Lightpart lp;
    __u32 threshold;
};

#endif
