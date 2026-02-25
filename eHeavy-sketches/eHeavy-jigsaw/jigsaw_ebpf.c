#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "jigsaw_parameters.h"

#ifndef ETH_P_IP
#define ETH_P_IP 2048
#endif


struct pkt_5tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} insert_counter SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xdp_stats));
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct jigsaw_bucket));
    __uint(max_entries, BUCKET_NUM);
} bucket_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, AUX_LIST_WORDS);
} auxiliary_list_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} packets_per_window_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} packet_sequence_map SEC(".maps");


static __u32 rng_state = 0x12345678;

static __always_inline __u32 simple_random(void){
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}


static __always_inline __u64 get_packet_sequence_number(void){
    __u32 key = 0;
    __u64 *seq = bpf_map_lookup_elem(&packet_sequence_map, &key);
    if(!seq){
        __u64 init = 0;
        bpf_map_update_elem(&packet_sequence_map, &key, &init, BPF_ANY);
        return 0;
    }
    return __sync_fetch_and_add(seq, 1);
}


static __always_inline void divide_key(__u8 key[KEY_SIZE], __u32 *index, __u16 *fingerprint, __u64 residual_part[2]){
    __builtin_memcpy(residual_part, key, KEY_SIZE);
    
    __u64 part1 = residual_part[0] & MI_MASK;
    __u64 part2 = (residual_part[1] << 12) + (residual_part[0] >> 52);
    part1 = (part1 * MI_A) & MI_MASK;
    part2 = (part2 * MI_A) & MI_MASK;
    
    __u32 temp_parts[2] = {0};
    temp_parts[0] = (__u32)(part1 & MASK_26BITS) ^ (__u32)(part1 >> 26) ^ (__u32)(part2 & MASK_26BITS);
    temp_parts[1] = temp_parts[0] ^ (__u32)(part2 >> 26);
    temp_parts[1] ^= temp_parts[1] >> 13;
    
    residual_part[0] = part1 + (((__u64)(temp_parts[0] & 0xFFF)) << 52);
    residual_part[1] = (temp_parts[1]) + (((__u64)temp_parts[0] & (~0xFFF)) << 14);
    
    *index = residual_part[1] % BUCKET_NUM;
    residual_part[1] /= BUCKET_NUM;
    *fingerprint = residual_part[1] & 0xFFFF;
    residual_part[1] >>= 16;
}


static __always_inline __u8 get_residual_part(__u32 slot_index, __u64 residual_part[2]){
    __u32 slot_length = RESIDUAL_PART_BITS + SIGNAL_BITS;
    __u32 bit_idx = slot_index * slot_length;
    __u32 slot_word_idx = bit_idx / 64;
    __u32 slot_bit_idx_in_word = bit_idx % 64;
    
    __u32 extracted_bits = 0;
    __u32 rp_word_idx = 0;
    __u32 rp_bit_in_word = 0;
    
    residual_part[0] = 0;
    residual_part[1] = 0;
    
    
    #pragma unroll
    for (int iter = 0; iter < 4; iter++){
        if(extracted_bits >= slot_length) break;
        if(slot_word_idx >= AUX_LIST_WORDS) break;
        
        __u64 *aux_val = bpf_map_lookup_elem(&auxiliary_list_map, &slot_word_idx);
        if(!aux_val) break;
        
        __u32 to_extract = slot_length - extracted_bits;
        if(to_extract > (64 - rp_bit_in_word)) to_extract = 64 - rp_bit_in_word;
        if(to_extract > (64 - slot_bit_idx_in_word)) to_extract = 64 - slot_bit_idx_in_word;
        
        __u64 extract_part;
        if(to_extract == 64){
            extract_part = *aux_val;
        }
        else{
            __u64 mask = (((__u64)1) << to_extract) - 1;
            extract_part = (*aux_val >> slot_bit_idx_in_word) & mask;
        }
        
        if(rp_bit_in_word == 0 && rp_word_idx < 2){
            residual_part[rp_word_idx] = 0;
        }
        if(rp_word_idx < 2){
            residual_part[rp_word_idx] += extract_part << rp_bit_in_word;
        }
        
        bit_idx += to_extract;
        slot_word_idx = bit_idx / 64;
        slot_bit_idx_in_word = bit_idx % 64;
        extracted_bits += to_extract;
        rp_word_idx = extracted_bits / 64;
        rp_bit_in_word = extracted_bits % 64;
    }
    
    
    __u8 counter = 0;
    if(rp_word_idx < 2 && rp_bit_in_word >= 2){
        counter = residual_part[rp_word_idx] >> (rp_bit_in_word - 2);
        __u64 clear_mask = ~(((__u64)3) << (rp_bit_in_word - 2));
        residual_part[rp_word_idx] &= clear_mask;
    }
    
    return counter & 0x3;
}


static __always_inline void set_residual_part_field_of_al(__u32 slot_index, __u64 residual_part[2]){
    __u32 bit_idx = slot_index * (RESIDUAL_PART_BITS + SIGNAL_BITS);
    __u32 slot_word_idx = bit_idx / 64;
    __u32 slot_bit_idx_in_word = bit_idx % 64;
    
    __u32 extracted_bits = 0;
    __u32 rp_word_idx = 0;
    __u32 rp_bit_in_word = 0;
    
    #pragma unroll
    for (int iter = 0; iter < 4; iter++){
        if(extracted_bits >= RESIDUAL_PART_BITS) break;
        if(slot_word_idx >= AUX_LIST_WORDS) break;
        
        __u64 *aux_val = bpf_map_lookup_elem(&auxiliary_list_map, &slot_word_idx);
        if(!aux_val) break;
        
        __u32 to_extract = RESIDUAL_PART_BITS - extracted_bits;
        if(to_extract > (64 - rp_bit_in_word)) to_extract = 64 - rp_bit_in_word;
        if(to_extract > (64 - slot_bit_idx_in_word)) to_extract = 64 - slot_bit_idx_in_word;
        
        __u64 extract_part;
        __u64 mask;
        
        if(to_extract == 64){
            extract_part = (rp_word_idx < 2) ? residual_part[rp_word_idx] : 0;
            __u64 new_val = extract_part;
            bpf_map_update_elem(&auxiliary_list_map, &slot_word_idx, &new_val, BPF_ANY);
        }
        else{
            mask = (((__u64)1) << to_extract) - 1;
            extract_part = (rp_word_idx < 2) ? ((residual_part[rp_word_idx] >> rp_bit_in_word) & mask) : 0;
            
            __u64 old_val = *aux_val;
            old_val &= ~(mask << slot_bit_idx_in_word);
            old_val += extract_part << slot_bit_idx_in_word;
            bpf_map_update_elem(&auxiliary_list_map, &slot_word_idx, &old_val, BPF_ANY);
        }
        
        bit_idx += to_extract;
        slot_word_idx = bit_idx / 64;
        slot_bit_idx_in_word = bit_idx % 64;
        extracted_bits += to_extract;
        rp_word_idx = extracted_bits / 64;
        rp_bit_in_word = extracted_bits % 64;
    }
}


static __always_inline void set_signal_field_of_al(__u32 slot_index, __u8 counter){
    __u32 bit_idx = slot_index * (RESIDUAL_PART_BITS + SIGNAL_BITS) + RESIDUAL_PART_BITS;
    __u32 slot_word_idx = bit_idx / 64;
    __u32 slot_bit_idx_in_word = bit_idx % 64;
    if(slot_word_idx >= AUX_LIST_WORDS) return;
    
    __u64 *aux_val = bpf_map_lookup_elem(&auxiliary_list_map, &slot_word_idx);
    if(!aux_val) return;
    
    __u32 extracted_bits = 0;
    
    #pragma unroll
    for (int iter = 0; iter < 2; iter++){
        if(extracted_bits >= SIGNAL_BITS) break;
        if(slot_word_idx >= AUX_LIST_WORDS) break;
        
        __u32 to_extract = SIGNAL_BITS - extracted_bits;
        if(to_extract > (64 - slot_bit_idx_in_word)) to_extract = 64 - slot_bit_idx_in_word;
        
        __u64 mask = (((__u64)1) << to_extract) - 1;
        __u64 extract_part = (counter >> extracted_bits) & mask;
        
        __u64 old_val = *aux_val;
        old_val &= ~(mask << slot_bit_idx_in_word);
        old_val += extract_part << slot_bit_idx_in_word;
        bpf_map_update_elem(&auxiliary_list_map, &slot_word_idx, &old_val, BPF_ANY);
        
        bit_idx += to_extract;
        slot_word_idx = bit_idx / 64;
        slot_bit_idx_in_word = bit_idx % 64;
        extracted_bits += to_extract;
    }
}

static __always_inline __u16 get_current_window_id(__u64 packet_seq, __u64 packets_per_window){
    if(packets_per_window == 0) return 0;
    return (__u16)(packet_seq / packets_per_window);
}


static __always_inline void jigsaw_insert(__u8 key[KEY_SIZE], __u64 current_seq_num, __u64 packet_size){
    __u32 key_ppw = 0;
    __u32 *ppw_ptr = bpf_map_lookup_elem(&packets_per_window_map, &key_ppw);
    __u32 packets_per_window = ppw_ptr ? *ppw_ptr : 250000; 

    if(packets_per_window == 0){
        packets_per_window = 1600;  
    }

    __u32 bucket_idx;
    __u16 fp;
    __u64 residual_part[2] = {0, 0};
    
    __u64 smallest_heavy_flow_size = 0;
    __u64 smallest_cell_flow_size = 0;
    __u64 matched_cell_flow_size = 0;

    divide_key(key, &bucket_idx, &fp, residual_part);
    
    struct jigsaw_bucket *bucket = bpf_map_lookup_elem(&bucket_map, &bucket_idx);
    if(!bucket) return;
    
    __u16 current_window_id = get_current_window_id(current_seq_num, packets_per_window);

    int matched_cell_idx = -1;
    __u32 matched_cell_counter = 0;
    
    int smallest_heavy_idx = -1;
    __u16 smallest_heavy_fp = 0;
    __u32 smallest_heavy_counter = 0xFFFFFFFF;
    
    
    #pragma unroll
    for (int i = 0; i < CELL_NUM_H; i++){
        __u16 cell_fp = bucket->cells[i].fp;
        __u32 cell_counter = bucket->cells[i].counter;
        __u64 cell_flow_size = bucket->cells[i].flow_size;
        
        
        if(cell_counter == 0){
            bucket->cells[i].fp = fp;
            bucket->cells[i].counter = 1;
            bucket->cells[i].flow_size = packet_size;
            bucket->cells[i].first_seen_window_id = current_window_id;
            bucket->cells[i].last_seen_window_id = current_window_id;

            __u32 slot_index = bucket_idx * CELL_NUM_H + i;
            set_residual_part_field_of_al(slot_index, residual_part);
            return;
        }
        
        
        if(fp == cell_fp && cell_counter > 0){
            matched_cell_idx = i;
            matched_cell_counter = cell_counter;
            matched_cell_flow_size = cell_flow_size;
            break;
        }
        
        
        if(cell_counter < smallest_heavy_counter){
            smallest_heavy_idx = i;
            smallest_heavy_fp = cell_fp;
            smallest_heavy_counter = cell_counter;
            smallest_heavy_flow_size = cell_flow_size;
        }
    }
    
    int smallest_cell_idx = smallest_heavy_idx;
    __u32 smallest_cell_counter = smallest_heavy_counter;
    
    
    if(matched_cell_idx < 0){
        #pragma unroll
        for (int i = CELL_NUM_H; i < CELL_NUM_H + CELL_NUM_L; i++){
            __u16 cell_fp = bucket->cells[i].fp;
            __u32 cell_counter = bucket->cells[i].counter;
            __u64 cell_flow_size = bucket->cells[i].flow_size;

            
            if(cell_counter == 0){
                bucket->cells[i].fp = fp;
                bucket->cells[i].counter = 1;
                bucket->cells[i].flow_size = packet_size;
                bucket->cells[i].first_seen_window_id = current_window_id;
                bucket->cells[i].last_seen_window_id = current_window_id;
                return;
            }
            
            
            if(fp == cell_fp && cell_counter > 0){
                matched_cell_idx = i;
                matched_cell_counter = cell_counter;
                matched_cell_flow_size = cell_flow_size;
                break;
            }
            
            
            if(cell_counter < smallest_cell_counter){
                smallest_cell_idx = i;
                smallest_cell_counter = cell_counter;
                smallest_cell_flow_size = cell_flow_size;
            }
        }
    }
    
    
    if(matched_cell_idx < 0){
        if(smallest_cell_counter > 0){
            __u32 rand = simple_random();
            
            if((rand % smallest_cell_counter) == 0){
                if(smallest_cell_idx >= 0){
                    bucket->cells[smallest_cell_idx].fp = fp;
                    bucket->cells[smallest_cell_idx].counter = 1;
                    bucket->cells[smallest_cell_idx].flow_size = packet_size;
                    bucket->cells[smallest_cell_idx].first_seen_window_id = current_window_id;
                    bucket->cells[smallest_cell_idx].last_seen_window_id = current_window_id;
                }
                if(smallest_cell_idx >= 0 && smallest_cell_idx < CELL_NUM_H){
                    __u32 slot_index = bucket_idx * CELL_NUM_H + smallest_cell_idx;
                    set_residual_part_field_of_al(slot_index, residual_part);
                }
            }
        }
        return;
    }
    
    
    if(matched_cell_idx >= CELL_NUM_H){
        
        if((matched_cell_counter + 1) > smallest_heavy_counter && matched_cell_idx >= 0 && smallest_heavy_idx >= 0){
            __u32 first = bucket->cells[matched_cell_idx].first_seen_window_id;

            bucket->cells[matched_cell_idx].fp = smallest_heavy_fp;
            bucket->cells[matched_cell_idx].counter = smallest_heavy_counter;
            bucket->cells[matched_cell_idx].flow_size = 0;
            bucket->cells[matched_cell_idx].first_seen_window_id = bucket->cells[smallest_heavy_idx].first_seen_window_id;
            bucket->cells[matched_cell_idx].last_seen_window_id = bucket->cells[smallest_heavy_idx].last_seen_window_id;

            bucket->cells[smallest_heavy_idx].fp = fp;
            bucket->cells[smallest_heavy_idx].counter = matched_cell_counter + 1;
            bucket->cells[smallest_heavy_idx].flow_size = packet_size;
            bucket->cells[smallest_heavy_idx].first_seen_window_id = first;
            bucket->cells[smallest_heavy_idx].last_seen_window_id = current_window_id;
            
            __u32 slot_index = bucket_idx * CELL_NUM_H + smallest_heavy_idx;
            set_residual_part_field_of_al(slot_index, residual_part);
        }
        else{
            bucket->cells[matched_cell_idx].counter = matched_cell_counter + 1;
            bucket->cells[matched_cell_idx].flow_size += packet_size;
            bucket->cells[matched_cell_idx].last_seen_window_id = current_window_id;
        }
    }
    else{
        
        bucket->cells[matched_cell_idx].counter = matched_cell_counter + 1;
        bucket->cells[matched_cell_idx].flow_size += packet_size;
        bucket->cells[matched_cell_idx].last_seen_window_id = current_window_id;
        
        
        __u32 new_counter_value = matched_cell_counter + 1;
        if((new_counter_value) == AL_THRESHOLD || 
            ((new_counter_value) > AL_THRESHOLD && (simple_random() % new_counter_value) == 0)){ 
            __u32 slot_index = bucket_idx * CELL_NUM_H + matched_cell_idx;
            __u64 target_residual_part[2] = {0, 0};
            __u8 signal = get_residual_part(slot_index, target_residual_part);
            
            
            int residual_part_match = 1;
            #pragma unroll
            for (int j = 0; j < 10; j++){
                if(((__u8*)residual_part)[j] != ((__u8*)target_residual_part)[j]){
                    residual_part_match = 0;
                    break;
                }
            }
            
            if(!residual_part_match){
                if(signal > 0) set_signal_field_of_al(slot_index, signal - 1);
                else set_residual_part_field_of_al(slot_index, residual_part);
            } 
            else{
                if(signal < 3) set_signal_field_of_al(slot_index, signal + 1);
            }
        }
    }
}

static __always_inline int parse_packet(struct xdp_md *ctx, struct pkt_5tuple *tuple){
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    
    struct ethhdr *eth = data;
    if((void *)(eth + 1) > data_end)
        return -1;
    
    
    if(eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    
    struct iphdr *ip = (void *)(eth + 1);
    if((void *)(ip + 1) > data_end)
        return -1;
    
    
    __u32 ihl = ip->ihl;
    if(ihl < 5)
        return -1;
    
    __u32 ip_hdr_len = ihl * 4;
    
    
    if((void *)ip + ip_hdr_len > data_end)
        return -1;
    
    
    tuple->src_ip = ip->saddr;
    tuple->dst_ip = ip->daddr;
    tuple->proto  = ip->protocol;
    
    
    void *l4 = (void *)ip + ip_hdr_len;
    
    
    if(tuple->proto == IPPROTO_TCP){
        struct tcphdr *tcp = l4;
        if((void *)(tcp + 1) > data_end)
            return -1;
        tuple->src_port = tcp->source;
        tuple->dst_port = tcp->dest;
    }
    else if(tuple->proto == IPPROTO_UDP){
        struct udphdr *udp = l4;
        if((void *)(udp + 1) > data_end)
            return -1;
        tuple->src_port = udp->source;
        tuple->dst_port = udp->dest;
    }
    else{
        
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    
    return 0;
}

SEC("xdp")
int jigsaw_xdp(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_size = (__u64)(data_end - data);

    
    struct pkt_5tuple tuple = {0};
    if(parse_packet(ctx, &tuple) < 0)
        return XDP_PASS;

    
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if(stats){
        __u64 bytes = data_end - data;
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
    
    
    __u8 flow_key[KEY_SIZE] = {0};
    
    
    flow_key[0] = (tuple.src_ip >> 0) & 0xFF;
    flow_key[1] = (tuple.src_ip >> 8) & 0xFF;
    flow_key[2] = (tuple.src_ip >> 16) & 0xFF;
    flow_key[3] = (tuple.src_ip >> 24) & 0xFF;
    
    flow_key[4] = (tuple.dst_ip >> 0) & 0xFF;
    flow_key[5] = (tuple.dst_ip >> 8) & 0xFF;
    flow_key[6] = (tuple.dst_ip >> 16) & 0xFF;
    flow_key[7] = (tuple.dst_ip >> 24) & 0xFF;
    
    __u16 sport = bpf_ntohs(tuple.src_port);
    __u16 dport = bpf_ntohs(tuple.dst_port);
    
    flow_key[8] = (sport >> 8) & 0xFF;
    flow_key[9] = sport & 0xFF;
    flow_key[10] = (dport >> 8) & 0xFF;
    flow_key[11] = dport & 0xFF;
    flow_key[12] = tuple.proto;
    
    
    rng_state = flow_key[0] ^ (flow_key[1] << 8) ^ (flow_key[2] << 16) ^ (flow_key[3] << 24) ^ bpf_ktime_get_ns();

    __u64 current_seq_num = get_packet_sequence_number();
    
    jigsaw_insert(flow_key, current_seq_num, packet_size);
 
 __u32 counter_key=0;
 __u64 *val = bpf_map_lookup_elem(&insert_counter, &counter_key);
  if (val)
    __sync_fetch_and_add(val, 1);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
