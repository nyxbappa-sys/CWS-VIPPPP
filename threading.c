#include "core.h"

pthread_t threads[1000];
int thread_count = 0;

void* cws_thread_wrapper(void* arg) {
    void* (*func)(void*) = (void* (*)(void*))arg;
    return func(NULL);
}

int cws_thread_create(void* (*func)(void*)) {
    if(thread_count >= 1000) return -1;
    pthread_create(&threads[thread_count], NULL, cws_thread_wrapper, func);
    thread_count++;
    return thread_count - 1;
}

void cws_thread_join(int id) {
    if(id >= 0 && id < thread_count) {
        pthread_join(threads[id], NULL);
    }
}

void cws_thread_join_all() {
    for(int i=0; i<thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
}

void cws_thread_kill_all() {
    for(int i=0; i<thread_count; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }
    thread_count = 0;
}
