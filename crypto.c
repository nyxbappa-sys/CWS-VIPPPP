#include "core.h"

char* cws_xor_encrypt(char* s, char* key) {
    static char result[1000000];
    int key_len = strlen(key);
    int s_len = strlen(s);
    for(int i=0; i<s_len; i++) {
        result[i] = s[i] ^ key[i % key_len];
    }
    result[s_len] = 0;
    return result;
}

char* cws_xor_decrypt(char* s, char* key) {
    return cws_xor_encrypt(s, key);
}

char* cws_generate_key(int length) {
    static char key[4096];
    char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    int char_count = strlen(chars);
    srand(time(NULL) ^ getpid());
    for(int i=0; i<length && i<4095; i++) {
        key[i] = chars[rand() % char_count];
    }
    key[length] = 0;
    return key;
}

char* cws_generate_session() {
    static char sid[64];
    time_t now = time(NULL);
    sprintf(sid, "%lx%lx%lx", (unsigned long)now, (unsigned long)getpid(), (unsigned long)rand());
    return sid;
}

char* cws_hash_md5(char* data) {
    static char result[33];
    unsigned long hash = 5381;
    for(int i=0; data[i]; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    sprintf(result, "%016lx", hash);
    return result;
}
