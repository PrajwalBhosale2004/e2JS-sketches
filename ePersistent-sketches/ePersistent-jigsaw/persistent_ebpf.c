#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "persistent_parameters.h"

#ifndef ETH_P_IP
#define ETH_P_IP 2048
#endif


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xdp_stats));
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct persistent_bucket));
    __uint(max_entries, BUCKET_NUM);
} persistent_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, AUX_LIST_WORDS);
} auxiliary_list_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} packet_sequence_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} packets_per_window_map SEC(".maps");


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
    __u32 lp_word_idx = 0;
    __u32 lp_bit_in_word = 0;
    
    residual_part[0] = 0;
    residual_part[1] = 0;
    
    #pragma unroll
    for (int iter = 0; iter < 4; iter++){
        if(extracted_bits >= slot_length) break;
        if(slot_word_idx >= AUX_LIST_WORDS) break;
        
        __u64 *aux_val = bpf_map_lookup_elem(&auxiliary_list_map, &slot_word_idx);
        if(!aux_val) break;
        
        __u32 to_extract = slot_length - extracted_bits;
        if(to_extract > (64 - lp_bit_in_word)) to_extract = 64 - lp_bit_in_word;
        if(to_extract > (64 - slot_bit_idx_in_word)) to_extract = 64 - slot_bit_idx_in_word;
        
        __u64 extract_part;
        if(to_extract == 64){
            extract_part = *aux_val;
        } else{
            __u64 mask = (((__u64)1) << to_extract) - 1;
            extract_part = (*aux_val >> slot_bit_idx_in_word) & mask;
        }
        
        if(lp_bit_in_word == 0 && lp_word_idx < 2){
            residual_part[lp_word_idx] = 0;
        }
        if(lp_word_idx < 2){
            residual_part[lp_word_idx] += extract_part << lp_bit_in_word;
        }
        
        bit_idx += to_extract;
        slot_word_idx = bit_idx / 64;
        slot_bit_idx_in_word = bit_idx % 64;
        extracted_bits += to_extract;
        lp_word_idx = extracted_bits / 64;
        lp_bit_in_word = extracted_bits % 64;
    }
    
    __u8 counter = 0;
    if(lp_word_idx < 2 && lp_bit_in_word >= 2){
        counter = residual_part[lp_word_idx] >> (lp_bit_in_word - 2);
        __u64 clear_mask = ~(((__u64)3) << (lp_bit_in_word - 2));
        residual_part[lp_word_idx] &= clear_mask;
    }
    
    return counter & 0x3;
}


static __always_inline void set_residual_part_field_of_al(__u32 slot_index, __u64 residual_part[2]){
    __u32 bit_idx = slot_index * (RESIDUAL_PART_BITS + SIGNAL_BITS);
    __u32 slot_word_idx = bit_idx / 64;
    __u32 slot_bit_idx_in_word = bit_idx % 64;
    
    __u32 extracted_bits = 0;
    __u32 lp_word_idx = 0;
    __u32 lp_bit_in_word = 0;
    
    #pragma unroll
    for (int iter = 0; iter < 4; iter++){
        if(extracted_bits >= RESIDUAL_PART_BITS) break;
        if(slot_word_idx >= AUX_LIST_WORDS) break;
        
        __u64 *aux_val = bpf_map_lookup_elem(&auxiliary_list_map, &slot_word_idx);
        if(!aux_val) break;
        
        __u32 to_extract = RESIDUAL_PART_BITS - extracted_bits;
        if(to_extract > (64 - lp_bit_in_word)) to_extract = 64 - lp_bit_in_word;
        if(to_extract > (64 - slot_bit_idx_in_word)) to_extract = 64 - slot_bit_idx_in_word;
        
        __u64 extract_part;
        __u64 mask;
        
        if(to_extract == 64){
            extract_part = (lp_word_idx < 2) ? residual_part[lp_word_idx] : 0;
            __u64 new_val = extract_part;
            bpf_map_update_elem(&auxiliary_list_map, &slot_word_idx, &new_val, BPF_ANY);
        } else{
            mask = (((__u64)1) << to_extract) - 1;
            extract_part = (lp_word_idx < 2) ? 
                          ((residual_part[lp_word_idx] >> lp_bit_in_word) & mask) : 0;
            
            __u64 old_val = *aux_val;
            old_val &= ~(mask << slot_bit_idx_in_word);
            old_val += extract_part << slot_bit_idx_in_word;
            bpf_map_update_elem(&auxiliary_list_map, &slot_word_idx, &old_val, BPF_ANY);
        }
        
        bit_idx += to_extract;
        slot_word_idx = bit_idx / 64;
        slot_bit_idx_in_word = bit_idx % 64;
        extracted_bits += to_extract;
        lp_word_idx = extracted_bits / 64;
        lp_bit_in_word = extracted_bits % 64;
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


static __always_inline __u16 get_current_window(__u64 packet_seq, __u64 packets_per_window){
    if(packets_per_window == 0) return 0;
    return (__u32)(packet_seq / packets_per_window);
}


static __always_inline void persistent_insert(__u8 key[KEY_SIZE], __u64 current_seq, __u64 packet_size){
    __u32 key_ppw = 0;
    __u32 *ppw_ptr = bpf_map_lookup_elem(&packets_per_window_map, &key_ppw);
    __u32 packets_per_window = ppw_ptr ? *ppw_ptr : 250000; 

    if(packets_per_window == 0){
        packets_per_window = 1600;  
    }

    __u32 bucket_idx;
    __u16 fp;
    __u64 residual_part[2] = {0, 0};

    divide_key(key, &bucket_idx, &fp, residual_part);

    struct persistent_bucket *bucket = bpf_map_lookup_elem(&persistent_map, &bucket_idx);
    if(!bucket) return;

    __u16 current_window = get_current_window(current_seq, packets_per_window);

    int smallest_heavy_idx = -1;
    int smallest_idx = -1;
    __u16 smallest_heavy_cell_window_count = 0xFFFF;
    __u16 smallest_all_cell_window_count = 0xFFFF;

    #pragma unroll
    for(int i = 0; i < CELL_NUM_H; i++){
        if(bucket->cells[i].window_count == 0){
            
            bucket->cells[i].fp = fp;
            bucket->cells[i].window_count = 1;
            bucket->cells[i].last_seen_window_id = current_window;
            bucket->cells[i].flow_size = packet_size;
            bucket->cells[i].first_seen_window_id = current_window;

            if(i < CELL_NUM_H){
                __u32 slot_index = bucket_idx * CELL_NUM_H + i;
                set_residual_part_field_of_al(slot_index, residual_part);
                set_signal_field_of_al(slot_index, 0);
            }
            return;
        }

        if(bucket->cells[i].fp == fp){
            
            bucket->cells[i].flow_size += packet_size;
            int is_new_window = (bucket->cells[i].last_seen_window_id != current_window);
            
            if(is_new_window){
                bucket->cells[i].window_count += 1;
                bucket->cells[i].last_seen_window_id = current_window;
            }

            
            if(i >= CELL_NUM_H && 
               bucket->cells[i].window_count > smallest_heavy_cell_window_count && 
               smallest_heavy_idx != -1){
                
                
                __u16 temp_fp = bucket->cells[smallest_heavy_idx].fp;
                __u16 temp_window_count = bucket->cells[smallest_heavy_idx].window_count;
                __u32 temp_last_seen_window_id = bucket->cells[smallest_heavy_idx].last_seen_window_id;
                __u64 temp_flow_size = bucket->cells[smallest_heavy_idx].flow_size;
                __u32 temp_first_seen_window_id = bucket->cells[smallest_heavy_idx].first_seen_window_id;

                bucket->cells[smallest_heavy_idx].fp = bucket->cells[i].fp;
                bucket->cells[smallest_heavy_idx].window_count = bucket->cells[i].window_count;
                bucket->cells[smallest_heavy_idx].last_seen_window_id = bucket->cells[i].last_seen_window_id;
                bucket->cells[smallest_heavy_idx].flow_size = bucket->cells[i].flow_size;
                bucket->cells[smallest_heavy_idx].first_seen_window_id = bucket->cells[i].first_seen_window_id;

                bucket->cells[i].fp = temp_fp;
                bucket->cells[i].window_count = temp_window_count;
                bucket->cells[i].last_seen_window_id = temp_last_seen_window_id;
                bucket->cells[i].flow_size = temp_flow_size;
                bucket->cells[i].first_seen_window_id = temp_first_seen_window_id;
                
                
                __u32 slot_index = bucket_idx * CELL_NUM_H + smallest_heavy_idx;
                set_residual_part_field_of_al(slot_index, residual_part);
                set_signal_field_of_al(slot_index, 0);
            }

            
            if(i < CELL_NUM_H && is_new_window){
                __u32 slot_index = bucket_idx * CELL_NUM_H + i;
                __u64 stored_residual_part[2] = {0, 0};
                __u8 signal = get_residual_part(slot_index, stored_residual_part);

                
                int residual_parts_match = 1;
                #pragma unroll
                for (int j = 0; j < 10; j++){
                    if(((__u8*)residual_part)[j] != ((__u8*)stored_residual_part)[j]){
                        residual_parts_match = 0;
                        break;
                    }
                }

                if(residual_parts_match){
                    
                    if(signal < 3){
                        set_signal_field_of_al(slot_index, signal + 1);
                    }
                } 
                else{
                    
                    if(signal > 0){
                        
                        set_signal_field_of_al(slot_index, signal - 1);
                    } 
                    else{
                        
                        set_residual_part_field_of_al(slot_index, residual_part);
                        set_signal_field_of_al(slot_index, 1);
                    }
                }
            }
            return;
        }

        
        if(i < CELL_NUM_H && bucket->cells[i].window_count < smallest_heavy_cell_window_count){
            smallest_heavy_cell_window_count = bucket->cells[i].window_count;
            smallest_heavy_idx = i;
        }

        if(bucket->cells[i].window_count < smallest_all_cell_window_count){
            smallest_all_cell_window_count = bucket->cells[i].window_count;
            smallest_idx = i;
        }
    }

    
    if(smallest_idx >= 0 && smallest_all_cell_window_count > 0){
        __u32 rand = simple_random();

        if((rand % smallest_all_cell_window_count) == 0){
            bucket->cells[smallest_idx].fp = fp;
            bucket->cells[smallest_idx].window_count = 1;
            bucket->cells[smallest_idx].last_seen_window_id = current_window;
            bucket->cells[smallest_idx].flow_size = packet_size;
            bucket->cells[smallest_idx].first_seen_window_id = current_window;

            if(smallest_idx < CELL_NUM_H){
                __u32 slot_index = bucket_idx * CELL_NUM_H + smallest_idx;
                set_residual_part_field_of_al(slot_index, residual_part);
                set_signal_field_of_al(slot_index, 0);
            }
        }
    }
}

SEC("xdp")
int persistent_xdp(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_size = (__u64)(data_end - data);

    
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if(stats){
        __u64 bytes = data_end - data;
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
    
    
    struct ethhdr *eth = data;
    if((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if(eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    
    struct iphdr *ip = (void *)(eth + 1);
    if((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u8 flow_key[KEY_SIZE] = {0};
    
    
    flow_key[0] = (ip->saddr >> 0) & 0xFF;
    flow_key[1] = (ip->saddr >> 8) & 0xFF;
    flow_key[2] = (ip->saddr >> 16) & 0xFF;
    flow_key[3] = (ip->saddr >> 24) & 0xFF;
    
    flow_key[4] = (ip->daddr >> 0) & 0xFF;
    flow_key[5] = (ip->daddr >> 8) & 0xFF;
    flow_key[6] = (ip->daddr >> 16) & 0xFF;
    flow_key[7] = (ip->daddr >> 24) & 0xFF;
    
    __u16 sport = 0, dport = 0;
    
    if(ip->protocol == IPPROTO_TCP){
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if((void *)(tcp + 1) > data_end) return XDP_PASS;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } 
    else if(ip->protocol == IPPROTO_UDP){
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if((void *)(udp + 1) > data_end) return XDP_PASS;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }
    
    flow_key[8] = (sport >> 8) & 0xFF;
    flow_key[9] = sport & 0xFF;
    flow_key[10] = (dport >> 8) & 0xFF;
    flow_key[11] = dport & 0xFF;
    flow_key[12] = ip->protocol;
    
    
    rng_state = flow_key[0] ^ (flow_key[1] << 8) ^ (flow_key[2] << 16) ^ (flow_key[3] << 24) ^ bpf_ktime_get_ns();

    
    __u64 current_seq = get_packet_sequence_number();
    
    persistent_insert(flow_key, current_seq, packet_size);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";