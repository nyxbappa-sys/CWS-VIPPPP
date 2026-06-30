#include "core.h"

int secure_mode_enabled = 0;
char* secure_key = NULL;

void cws_security_init() {
    secure_key = cws_generate_key(256);
    secure_mode_enabled = 1;
}

void cws_security_cleanup() {
    if(secure_key) {
        cws_secure_wipe(secure_key, strlen(secure_key));
        free(secure_key);
        secure_key = NULL;
    }
    secure_mode_enabled = 0;
}

int cws_security_check() {
    return secure_mode_enabled;
}

void cws_security_enable() {
    secure_mode_enabled = 1;
}

void cws_security_disable() {
    secure_mode_enabled = 0;
}

char* cws_security_encrypt(char* data) {
    if(!secure_key) return data;
    return cws_xor_encrypt(data, secure_key);
}

char* cws_security_decrypt(char* data) {
    if(!secure_key) return data;
    return cws_xor_decrypt(data, secure_key);
}
