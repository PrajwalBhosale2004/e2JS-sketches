#ifndef ADAPTOR_H
#define ADAPTOR_H

#include "datatypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    FILE* file;
    char* buffer;
    size_t buffer_size;
    size_t current_pos;
    size_t bytes_loaded;
    long file_size;
    int eof_reached;
} adaptor_t;

static inline adaptor_t* adaptor_create(const char* filename, uint64_t buf_size) {
    adaptor_t* adaptor = (adaptor_t*)calloc(1, sizeof(adaptor_t));
    if (!adaptor) return NULL;
    
    adaptor->file = fopen(filename, "rb");
    if (!adaptor->file) {
        free(adaptor);
        return NULL;
    }
    
    // Get file size
    fseek(adaptor->file, 0, SEEK_END);
    adaptor->file_size = ftell(adaptor->file);
    fseek(adaptor->file, 0, SEEK_SET);
    
    adaptor->buffer_size = buf_size;
    adaptor->buffer = (char*)malloc(buf_size);
    if (!adaptor->buffer) {
        fclose(adaptor->file);
        free(adaptor);
        return NULL;
    }
    
    // Load initial data
    adaptor->bytes_loaded = fread(adaptor->buffer, 1, buf_size, adaptor->file);
    adaptor->current_pos = 0;
    adaptor->eof_reached = (adaptor->bytes_loaded < buf_size);
    
    return adaptor;
}

static inline void adaptor_destroy(adaptor_t* adaptor) {
    if (!adaptor) return;
    if (adaptor->file) fclose(adaptor->file);
    if (adaptor->buffer) free(adaptor->buffer);
    free(adaptor);
}

static inline void adaptor_reset(adaptor_t* adaptor) {
    if (!adaptor || !adaptor->file) return;
    fseek(adaptor->file, 0, SEEK_SET);
    adaptor->bytes_loaded = fread(adaptor->buffer, 1, adaptor->buffer_size, adaptor->file);
    adaptor->current_pos = 0;
    adaptor->eof_reached = (adaptor->bytes_loaded < adaptor->buffer_size);
}

static inline int adaptor_get_next(adaptor_t* adaptor, tuple_t* tuple) {
    if (!adaptor || !tuple) return 0;
    
    // Check if we need to reload buffer
    if (adaptor->current_pos + sizeof(tuple_t) > adaptor->bytes_loaded) {
        if (adaptor->eof_reached) {
            return 0; // No more data
        }
        // Reload buffer
        adaptor->bytes_loaded = fread(adaptor->buffer, 1, adaptor->buffer_size, adaptor->file);
        adaptor->current_pos = 0;
        adaptor->eof_reached = (adaptor->bytes_loaded < adaptor->buffer_size);
        
        if (adaptor->bytes_loaded == 0) {
            return 0;
        }
    }
    
    // Copy tuple from buffer
    memcpy(tuple, adaptor->buffer + adaptor->current_pos, sizeof(tuple_t));
    adaptor->current_pos += sizeof(tuple_t);
    
    return 1;
}

static inline uint64_t adaptor_get_data_size(adaptor_t* adaptor) {
    if (!adaptor) return 0;
    return (uint64_t)adaptor->file_size;
}

#endif // ADAPTOR_H