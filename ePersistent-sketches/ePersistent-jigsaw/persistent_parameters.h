#define KEY_SIZE 13

#define BUCKET_NUM 578
#define CELL_NUM_H 4
#define CELL_NUM_L 4

#define NUM_WINDOWS 1600
#define PERSISTENCE_THRESHOLD 0.5

#define RESIDUAL_PART_BITS 80
#define SIGNAL_BITS 2
#define AL_THRESHOLD 512

#define MI_A 2147483647ULL
#define MI_A_INV 4503597479886847ULL
#define MI_MASK 4503599627370495ULL
#define MASK_26BITS 0x3FFFFFF

#define AUX_LIST_WORDS ((BUCKET_NUM * CELL_NUM_H * (RESIDUAL_PART_BITS + SIGNAL_BITS) + 63) / 64)

struct xdp_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
};


struct persistent_cell {
    __u16 fp;              
    __u16 window_count;
    __u16 last_seen_window_id;
    __u64 flow_size;  
    __u16 first_seen_window_id;
};

struct persistent_bucket {
    struct persistent_cell cells[CELL_NUM_H + CELL_NUM_L];
};
