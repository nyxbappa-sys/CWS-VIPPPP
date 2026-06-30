#include "core.h"

void* cws_malloc(size_t size) {
    void* ptr = malloc(size);
    if(!ptr) {
        cws_fatal("MEMORY ALLOCATION FAILED");
    }
    return ptr;
}

void cws_free(void* ptr) {
    if(ptr) {
        cws_secure_wipe(ptr, sizeof(ptr));
        free(ptr);
    }
}

void* cws_calloc(size_t count, size_t size) {
    void* ptr = calloc(count, size);
    if(!ptr) {
        cws_fatal("MEMORY ALLOCATION FAILED");
    }
    return ptr;
}

void* cws_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if(!new_ptr) {
        cws_fatal("MEMORY REALLOCATION FAILED");
    }
    return new_ptr;
}

size_t cws_memory_usage() {
    return 0;
}

void cws_memory_dump() {
    printf("MEMORY DUMP\n");
}
