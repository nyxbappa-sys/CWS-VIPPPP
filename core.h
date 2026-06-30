#ifndef CWS_CORE_H
#define CWS_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>

#define CWS_VERSION "2.0.0"
#define CWS_BUILD "ENTERPRISE"

void cws_init();
void cws_cleanup();
void cws_error(char* msg, int line);
void cws_fatal(char* msg);
void cws_secure_wipe(void* data, size_t len);

char* cws_read_file(char* file);
void cws_write_file(char* file, char* content);
int cws_file_exists(char* file);
char* cws_file_checksum(char* file);

char* cws_trim(char* s);
char* cws_replace_all(char* s, char* old, char* new);
char* cws_append(char* a, char* b);
char* cws_clone(char* s);

char* cws_xor_encrypt(char* s, char* key);
char* cws_xor_decrypt(char* s, char* key);
char* cws_generate_key(int length);
char* cws_generate_session();

void cws_var_set(char* name, char* value);
void cws_var_set_secure(char* name, char* value);
char* cws_var_get(char* name);
void cws_var_delete(char* name);
void cws_var_export();
void cws_var_clear();
void cws_var_wipe();

void cws_module_register(char* name, char* path);
char* cws_module_load(char* name);

void cws_func_register(char* name, char* code);
char* cws_func_call(char* name, char** args, int arg_count);

int cws_thread_create(char* name, void* (*func)(void*), void* args);
void cws_thread_join_all();
void cws_thread_kill_all();

void cws_execute_file(char* file);
void cws_execute_line(char* line);
void cws_build_file(char* file, char* output);
void cws_encrypt_file(char* file, char* output, char* key);
void cws_decrypt_file(char* file, char* output, char* key);

#endif
