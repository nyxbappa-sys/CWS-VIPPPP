#include "core.h"

char* cws_read_file(char* file) {
    FILE* f = fopen(file, "rb");
    if(!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* s = malloc(len + 1);
    fread(s, 1, len, f);
    s[len] = 0;
    fclose(f);
    return s;
}

void cws_write_file(char* file, char* content) {
    FILE* f = fopen(file, "w");
    if(!f) return;
    fprintf(f, "%s", content);
    fclose(f);
}

int cws_file_exists(char* file) {
    struct stat st;
    return stat(file, &st) == 0;
}

char* cws_file_checksum(char* file) {
    static char result[65];
    char* data = cws_read_file(file);
    if(!data) return NULL;
    unsigned long hash = 5381;
    for(int i=0; data[i]; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    free(data);
    sprintf(result, "%016lx", hash);
    return result;
}

void cws_file_delete(char* file) {
    unlink(file);
}

void cws_file_copy(char* src, char* dst) {
    char* data = cws_read_file(src);
    if(data) {
        cws_write_file(dst, data);
        free(data);
    }
}
