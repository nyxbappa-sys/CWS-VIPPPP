#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "core/core.h"

#define VERSION "2.0.0"
#define BUILD "ENTERPRISE"
#define MAX_VARS 100000
#define MAX_LINE 8192
#define MAX_CODE 10000000
#define MAX_KEY 4096
#define MAX_STACK 10000
#define MAX_THREADS 1000
#define MAX_FILES 10000
#define MAX_MODULES 100
#define MAX_STRUCTS 100
#define MAX_FUNCS 200

typedef struct {
    char* name;
    char* type;
    char* value;
    unsigned int secure;
    unsigned int readonly;
    unsigned int encrypted;
    char* key;
    time_t created;
    time_t modified;
} CWSVar;

typedef struct {
    char* name;
    char* code;
    char* params[30];
    int param_count;
    unsigned int secure;
    unsigned int encrypted;
    char* key;
} CWSFunc;

typedef struct {
    char* name;
    char* fields[50];
    char* types[50];
    int field_count;
    unsigned int secure;
} CWSStruct;

typedef struct {
    char* name;
    char* path;
    unsigned int loaded;
    char* checksum;
} CWSModule;

typedef struct {
    char* name;
    void* (*func)(void*);
    void* args;
    pthread_t thread;
    unsigned int running;
    unsigned int secure;
} CWSThread;

CWSVar vars[MAX_VARS];
int var_count = 0;
CWSFunc funcs[MAX_FUNCS];
int func_count = 0;
CWSStruct structs[MAX_STRUCTS];
int struct_count = 0;
CWSModule modules[MAX_MODULES];
int module_count = 0;
CWSThread threads[MAX_THREADS];
int thread_count = 0;

char* current_file = NULL;
int line_number = 0;
int secure_mode = 0;
int debug_mode = 0;
int verbose_mode = 0;
char global_key[MAX_KEY] = "CWS2026ENTERPRISESUPERLONGENCRYPTIONKEYXOR256BIT";
char session_id[64];
time_t start_time;

jmp_buf error_jmp;

void cws_init();
void cws_cleanup();
void cws_error(char* msg, int line);
void cws_fatal(char* msg);
void cws_signal_handler(int sig);
void cws_secure_wipe(void* data, size_t len);

char* read_file(char* file);
void write_file(char* file, char* content);
int file_exists(char* file);
char* file_checksum(char* file);

char* trim_str(char* s);
char* str_replace_all(char* s, char* old, char* new);
char* str_append(char* a, char* b);
char* str_clone(char* s);
int str_is_number(char* s);
int str_is_boolean(char* s);

void var_set(char* name, char* value);
void var_set_secure(char* name, char* value);
void var_set_encrypted(char* name, char* value, char* key);
char* var_get(char* name);
char* var_get_secure(char* name);
void var_delete(char* name);
void var_export();
void var_clear();
void var_wipe_all();
void var_encrypt_all(char* key);
void var_decrypt_all(char* key);

void module_register(char* name, char* path);
char* module_load(char* name);

void register_func(char* name, char* code);
char* call_func(char* name, char** args, int arg_count);

char* generate_xor_key(int length);
char* generate_session_id();
char* encrypt_xor(char* s, char* key);
char* decrypt_xor(char* s, char* key);
char* encrypt_xor_secure(char* s, char* key);
char* decrypt_xor_secure(char* s, char* key);
void encrypt_file_content(char* file, char* output, char* key);
void decrypt_file_content(char* file, char* output, char* key);

void* thread_start(void* arg);
int thread_create(char* name, void* (*func)(void*), void* args, unsigned int secure);
void thread_join_all();
void thread_kill_all();

void execute_line(char* line);
void execute_file(char* file, int secure);
void execute_secure_file(char* file, char* key);
void execute_encrypted_file(char* file, char* key);

void build_file(char* file, char* output);
void build_file_decrypted(char* code, char* output);
void build_secure_file(char* file, char* output, char* key);

void show_help();
void show_version();

int main(int argc, char** argv) {
    cws_init();
    
    if(argc < 2) {
        show_help();
        cws_cleanup();
        return 1;
    }
    
    if(strcmp(argv[1], "--version") == 0) {
        show_version();
        cws_cleanup();
        return 0;
    }
    
    if(strcmp(argv[1], "--help") == 0) {
        show_help();
        cws_cleanup();
        return 0;
    }
    
    if(strcmp(argv[1], "run") == 0) {
        if(argc < 3) {
            cws_error("MISSING FILE", 0);
            cws_cleanup();
            return 1;
        }
        int secure = 0;
        char* file = argv[2];
        char* key = NULL;
        
        for(int i=3; i<argc; i++) {
            if(strcmp(argv[i], "--secure") == 0) secure = 1;
            if(strcmp(argv[i], "--debug") == 0) debug_mode = 1;
            if(strcmp(argv[i], "--verbose") == 0) verbose_mode = 1;
            if(strcmp(argv[i], "-k") == 0 && i+1 < argc) key = argv[++i];
        }
        
        if(key) {
            execute_encrypted_file(file, key);
        } else if(secure) {
            execute_secure_file(file, global_key);
        } else {
            execute_file(file, 0);
        }
        
        cws_cleanup();
        return 0;
    }
    
    if(strcmp(argv[1], "build") == 0) {
        if(argc < 5 || strcmp(argv[3], "-o") != 0) {
            cws_error("build file.cws -o output", 0);
            cws_cleanup();
            return 1;
        }
        char* key = NULL;
        int secure = 0;
        
        for(int i=5; i<argc; i++) {
            if(strcmp(argv[i], "--secure") == 0) secure = 1;
            if(strcmp(argv[i], "-k") == 0 && i+1 < argc) key = argv[++i];
        }
        
        if(key) {
            build_secure_file(argv[2], argv[4], key);
        } else {
            build_file(argv[2], argv[4]);
        }
        
        cws_cleanup();
        return 0;
    }
    
    if(strcmp(argv[1], "encrypt") == 0) {
        if(argc < 5 || strcmp(argv[3], "-o") != 0) {
            cws_error("encrypt file.cws -o output -k key", 0);
            cws_cleanup();
            return 1;
        }
        char* key = global_key;
        for(int i=5; i<argc; i++) {
            if(strcmp(argv[i], "-k") == 0 && i+1 < argc) key = argv[++i];
        }
        encrypt_file_content(argv[2], argv[4], key);
        cws_cleanup();
        return 0;
    }
    
    if(strcmp(argv[1], "decrypt") == 0) {
        if(argc < 3) {
            cws_error("decrypt file.enc -k key", 0);
            cws_cleanup();
            return 1;
        }
        char* key = global_key;
        for(int i=3; i<argc; i++) {
            if(strcmp(argv[i], "-k") == 0 && i+1 < argc) key = argv[++i];
        }
        decrypt_file_content(argv[2], "decrypted_output.cws", key);
        cws_cleanup();
        return 0;
    }
    
    if(strcmp(argv[1], "clean") == 0) {
        var_clear();
        var_wipe_all();
        cws_cleanup();
        return 0;
    }
    
    cws_error("UNKNOWN COMMAND", 0);
    cws_cleanup();
    return 1;
}

void cws_init() {
    start_time = time(NULL);
    signal(SIGSEGV, cws_signal_handler);
    signal(SIGFPE, cws_signal_handler);
    signal(SIGABRT, cws_signal_handler);
    signal(SIGTERM, cws_signal_handler);
    signal(SIGINT, cws_signal_handler);
    
    generate_session_id();
    srand(time(NULL) ^ getpid());
    
    memset(vars, 0, sizeof(vars));
    memset(funcs, 0, sizeof(funcs));
    memset(structs, 0, sizeof(structs));
    memset(modules, 0, sizeof(modules));
    memset(threads, 0, sizeof(threads));
    
    var_count = 0;
    func_count = 0;
    struct_count = 0;
    module_count = 0;
    thread_count = 0;
}

void cws_cleanup() {
    var_clear();
    var_wipe_all();
    thread_kill_all();
    cws_secure_wipe(global_key, strlen(global_key));
    cws_secure_wipe(session_id, strlen(session_id));
}

void cws_error(char* msg, int line) {
    printf("CWS ERROR [%d]: %s\n", line, msg);
    if(debug_mode) {
        printf("DEBUG: File %s, Line %d\n", current_file ? current_file : "unknown", line);
    }
    longjmp(error_jmp, 1);
}

void cws_fatal(char* msg) {
    printf("CWS FATAL: %s\n", msg);
    cws_cleanup();
    exit(1);
}

void cws_signal_handler(int sig) {
    printf("CWS SIGNAL: %d\n", sig);
    cws_cleanup();
    exit(sig);
}

void cws_secure_wipe(void* data, size_t len) {
    unsigned char* p = (unsigned char*)data;
    for(size_t i = 0; i < len; i++) p[i] = 0x00;
    for(size_t i = 0; i < len; i++) p[i] = 0xFF;
    for(size_t i = 0; i < len; i++) p[i] = 0x00;
}

char* read_file(char* file) {
    FILE* f = fopen(file, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* s = malloc(len + 1);
    fread(s, 1, len, f);
    s[len] = 0;
    fclose(f);
    return s;
}

void write_file(char* file, char* content) {
    FILE* f = fopen(file, "w");
    if (!f) return;
    fprintf(f, "%s", content);
    fclose(f);
}

int file_exists(char* file) {
    struct stat st;
    return stat(file, &st) == 0;
}

char* file_checksum(char* file) {
    static char result[65];
    char* data = read_file(file);
    if(!data) return NULL;
    unsigned long hash = 5381;
    for(int i=0; data[i]; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    free(data);
    sprintf(result, "%016lx", hash);
    return result;
}

char* trim_str(char* s) {
    if(!s) return NULL;
    while(isspace(*s)) s++;
    if(*s == 0) return s;
    char* e = s + strlen(s) - 1;
    while(e > s && isspace(*e)) e--;
    *(e+1) = 0;
    return s;
}

char* str_replace_all(char* s, char* old, char* new) {
    static char buffer[MAX_CODE];
    char* p = s;
    char* result = buffer;
    int old_len = strlen(old);
    int new_len = strlen(new);
    while(*p) {
        if(strstr(p, old) == p) {
            strcpy(result, new);
            result += new_len;
            p += old_len;
        } else {
            *result++ = *p++;
        }
    }
    *result = 0;
    return buffer;
}

char* str_append(char* a, char* b) {
    static char buffer[MAX_CODE];
    sprintf(buffer, "%s%s", a, b);
    return buffer;
}

char* str_clone(char* s) {
    if(!s) return NULL;
    char* copy = malloc(strlen(s) + 1);
    strcpy(copy, s);
    return copy;
}

int str_is_number(char* s) {
    for(int i=0; s[i]; i++) {
        if(!isdigit(s[i]) && s[i] != '.' && s[i] != '-') return 0;
    }
    return 1;
}

int str_is_boolean(char* s) {
    return strcmp(s, "true") == 0 || strcmp(s, "false") == 0;
}

void var_set(char* name, char* value) {
    for(int i=0; i<var_count; i++) {
        if(strcmp(vars[i].name, name) == 0) {
            if(vars[i].readonly) {
                cws_error("READONLY VARIABLE", line_number);
                return;
            }
            free(vars[i].value);
            vars[i].value = str_clone(value);
            vars[i].modified = time(NULL);
            return;
        }
    }
    if(var_count >= MAX_VARS) {
        cws_error("MAX VARIABLES EXCEEDED", line_number);
        return;
    }
    vars[var_count].name = str_clone(name);
    vars[var_count].value = str_clone(value);
    vars[var_count].type = "auto";
    vars[var_count].secure = 0;
    vars[var_count].readonly = 0;
    vars[var_count].encrypted = 0;
    vars[var_count].key = NULL;
    vars[var_count].created = time(NULL);
    vars[var_count].modified = time(NULL);
    var_count++;
}

void var_set_secure(char* name, char* value) {
    var_set(name, value);
    for(int i=0; i<var_count; i++) {
        if(strcmp(vars[i].name, name) == 0) {
            vars[i].secure = 1;
            vars[i].readonly = 1;
            break;
        }
    }
}

void var_set_encrypted(char* name, char* value, char* key) {
    char* encrypted = encrypt_xor(value, key);
    var_set(name, encrypted);
    for(int i=0; i<var_count; i++) {
        if(strcmp(vars[i].name, name) == 0) {
            vars[i].encrypted = 1;
            vars[i].key = str_clone(key);
            break;
        }
    }
    free(encrypted);
}

char* var_get(char* name) {
    for(int i=0; i<var_count; i++) {
        if(strcmp(vars[i].name, name) == 0) {
            if(vars[i].secure && !secure_mode) {
                cws_error("SECURE VARIABLE ACCESS DENIED", line_number);
                return NULL;
            }
            if(vars[i].encrypted) {
                return decrypt_xor(vars[i].value, vars[i].key);
            }
            return vars[i].value;
        }
    }
    return NULL;
}

char* var_get_secure(char* name) {
    for(int i=0; i<var_count; i++) {
        if(strcmp(vars[i].name, name) == 0) {
            if(vars[i].secure) return vars[i].value;
        }
    }
    return NULL;
}

void var_delete(char* name) {
    for(int i=0; i<var_count; i++) {
        if(strcmp(vars[i].name, name) == 0) {
            free(vars[i].name);
            cws_secure_wipe(vars[i].value, strlen(vars[i].value));
            free(vars[i].value);
            if(vars[i].key) {
                cws_secure_wipe(vars[i].key, strlen(vars[i].key));
                free(vars[i].key);
            }
            for(int j=i; j<var_count-1; j++) {
                vars[j] = vars[j+1];
            }
            var_count--;
            return;
        }
    }
}

void var_export() {
    printf("VARIABLES: %d\n", var_count);
    for(int i=0; i<var_count; i++) {
        printf("[%d] %s = %s (secure=%d, encrypted=%d)\n", 
               i, vars[i].name, vars[i].value, 
               vars[i].secure, vars[i].encrypted);
    }
}

void var_clear() {
    for(int i=0; i<var_count; i++) {
        free(vars[i].name);
        if(vars[i].value) {
            cws_secure_wipe(vars[i].value, strlen(vars[i].value));
            free(vars[i].value);
        }
        if(vars[i].key) {
            cws_secure_wipe(vars[i].key, strlen(vars[i].key));
            free(vars[i].key);
        }
    }
    var_count = 0;
    memset(vars, 0, sizeof(vars));
}

void var_wipe_all() {
    for(int i=0; i<var_count; i++) {
        if(vars[i].value) cws_secure_wipe(vars[i].value, strlen(vars[i].value));
        if(vars[i].key) cws_secure_wipe(vars[i].key, strlen(vars[i].key));
    }
    var_clear();
}

void var_encrypt_all(char* key) {
    for(int i=0; i<var_count; i++) {
        if(!vars[i].encrypted) {
            char* encrypted = encrypt_xor(vars[i].value, key);
            free(vars[i].value);
            vars[i].value = encrypted;
            vars[i].encrypted = 1;
            vars[i].key = str_clone(key);
        }
    }
}

void var_decrypt_all(char* key) {
    for(int i=0; i<var_count; i++) {
        if(vars[i].encrypted) {
            char* decrypted = decrypt_xor(vars[i].value, key);
            free(vars[i].value);
            vars[i].value = decrypted;
            vars[i].encrypted = 0;
            free(vars[i].key);
            vars[i].key = NULL;
        }
    }
}

void module_register(char* name, char* path) {
    modules[module_count].name = str_clone(name);
    modules[module_count].path = str_clone(path);
    modules[module_count].loaded = 0;
    modules[module_count].checksum = NULL;
    module_count++;
}

char* module_load(char* name) {
    for(int i=0; i<module_count; i++) {
        if(strcmp(modules[i].name, name) == 0) {
            char* code = read_file(modules[i].path);
            if(code) {
                modules[i].loaded = 1;
                modules[i].checksum = file_checksum(modules[i].path);
                return code;
            }
        }
    }
    return NULL;
}

void register_func(char* name, char* code) {
    funcs[func_count].name = str_clone(name);
    funcs[func_count].code = str_clone(code);
    funcs[func_count].param_count = 0;
    func_count++;
}

char* call_func(char* name, char** args, int arg_count) {
    for(int i=0; i<func_count; i++) {
        if(strcmp(funcs[i].name, name) == 0) {
            char* code = str_clone(funcs[i].code);
            for(int j=0; j<arg_count && j<30; j++) {
                char param[10];
                sprintf(param, "$%d", j+1);
                code = str_replace_all(code, param, args[j]);
            }
            return code;
        }
    }
    return NULL;
}

char* generate_xor_key(int length) {
    static char key[MAX_KEY];
    char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    int char_count = strlen(chars);
    srand(time(NULL) ^ getpid() ^ rand());
    for(int i=0; i<length && i<MAX_KEY-1; i++) {
        key[i] = chars[rand() % char_count];
    }
    key[length] = 0;
    return key;
}

char* generate_session_id() {
    static char sid[64];
    time_t now = time(NULL);
    sprintf(sid, "%lx%lx%lx", (unsigned long)now, (unsigned long)getpid(), (unsigned long)rand());
    strcpy(session_id, sid);
    return sid;
}

char* encrypt_xor(char* s, char* key) {
    static char result[MAX_CODE];
    int key_len = strlen(key);
    int s_len = strlen(s);
    for(int i=0; i<s_len; i++) {
        result[i] = s[i] ^ key[i % key_len];
    }
    result[s_len] = 0;
    return result;
}

char* decrypt_xor(char* s, char* key) {
    return encrypt_xor(s, key);
}

char* encrypt_xor_secure(char* s, char* key) {
    static char result[MAX_CODE];
    int key_len = strlen(key);
    int s_len = strlen(s);
    for(int i=0; i<s_len; i++) {
        result[i] = (s[i] ^ key[i % key_len]) ^ (i * 0x55);
    }
    result[s_len] = 0;
    return result;
}

char* decrypt_xor_secure(char* s, char* key) {
    static char result[MAX_CODE];
    int key_len = strlen(key);
    int s_len = strlen(s);
    for(int i=0; i<s_len; i++) {
        result[i] = (s[i] ^ (i * 0x55)) ^ key[i % key_len];
    }
    result[s_len] = 0;
    return result;
}

void encrypt_file_content(char* file, char* output, char* key) {
    char* code = read_file(file);
    if(!code) {
        cws_error("FILE NOT FOUND", 0);
        return;
    }
    char* encrypted = encrypt_xor(code, key);
    write_file(output, encrypted);
    printf("ENCRYPTED: %s\n", output);
    free(code);
    free(encrypted);
}

void decrypt_file_content(char* file, char* output, char* key) {
    char* code = read_file(file);
    if(!code) {
        cws_error("FILE NOT FOUND", 0);
        return;
    }
    char* decrypted = decrypt_xor(code, key);
    write_file(output, decrypted);
    printf("DECRYPTED: %s\n", output);
    free(code);
    free(decrypted);
}

void* thread_start(void* arg) {
    CWSThread* t = (CWSThread*)arg;
    t->running = 1;
    t->func(t->args);
    t->running = 0;
    return NULL;
}

int thread_create(char* name, void* (*func)(void*), void* args, unsigned int secure) {
    if(thread_count >= MAX_THREADS) {
        cws_error("MAX THREADS EXCEEDED", line_number);
        return -1;
    }
    threads[thread_count].name = str_clone(name);
    threads[thread_count].func = func;
    threads[thread_count].args = args;
    threads[thread_count].secure = secure;
    threads[thread_count].running = 0;
    pthread_create(&threads[thread_count].thread, NULL, thread_start, &threads[thread_count]);
    thread_count++;
    return thread_count - 1;
}

void thread_join_all() {
    for(int i=0; i<thread_count; i++) {
        if(threads[i].running) {
            pthread_join(threads[i].thread, NULL);
        }
    }
}

void thread_kill_all() {
    for(int i=0; i<thread_count; i++) {
        if(threads[i].running) {
            pthread_cancel(threads[i].thread);
            pthread_join(threads[i].thread, NULL);
        }
    }
}

void execute_line(char* line) {
    line = trim_str(line);
    if(!line || line[0] == 0) return;
    
    if(line[0] == '#' || (line[0] == '/' && line[1] == '/') || line[0] == '*') {
        printf("INSULT: WEAK CODER COMMENTING CODE\n");
        printf("YOU ARE WEAK. THIS IS CWS.\n");
        return;
    }
    
    if(strstr(line, "cso") == line) {
        char* lib = line + 4;
        lib = trim_str(lib);
        if(lib[0] == '"' || lib[0] == '\'') {
            lib++;
            lib[strlen(lib)-1] = 0;
        }
        char* lib_code = module_load(lib);
        if(lib_code) {
            if(debug_mode) printf("MODULE LOADED: %s\n", lib);
            char* line2 = strtok(lib_code, "\n");
            while(line2) {
                execute_line(line2);
                line2 = strtok(NULL, "\n");
            }
            free(lib_code);
        } else {
            printf("MODULE NOT FOUND: %s\n", lib);
        }
        return;
    }
    
    if(strstr(line, "pef") == line) {
        char* rest = line + 4;
        rest = trim_str(rest);
        char* name = strtok(rest, " ");
        char* op = strtok(NULL, " ");
        char* value = strtok(NULL, "");
        if(name && op && strcmp(op, "?") == 0) {
            value = trim_str(value);
            if(value[0] == '"' || value[0] == '\'') {
                value++;
                value[strlen(value)-1] = 0;
            }
            var_set(name, value);
            if(debug_mode) printf("VAR SET: %s = %s\n", name, value);
        } else if(name && op && strcmp(op, "??") == 0) {
            value = trim_str(value);
            var_set_secure(name, value);
            if(debug_mode) printf("SECURE VAR SET: %s = %s\n", name, value);
        } else if(name && op && strcmp(op, "???") == 0) {
            value = trim_str(value);
            char* key = generate_xor_key(256);
            var_set_encrypted(name, value, key);
            if(debug_mode) printf("ENCRYPTED VAR SET: %s = %s\n", name, value);
        }
        return;
    }
    
    if(strstr(line, "cos") == line) {
        char* msg = line + 4;
        msg = trim_str(msg);
        if(msg[0] == '"' || msg[0] == '\'') {
            char* end = msg + strlen(msg) - 1;
            if((*end == '"' && msg[0] == '"') || (*end == '\'' && msg[0] == '\'')) {
                msg[strlen(msg)-1] = 0;
                msg++;
            }
            printf("%s\n", msg);
        } else {
            char* val = var_get(msg);
            if(val) printf("%s\n", val);
            else printf("NULL\n");
        }
        return;
    }
    
    if(strstr(line, "wso") == line) {
        char* rest = line + 4;
        rest = trim_str(rest);
        if(strstr(rest, "from") && strstr(rest, "to")) {
            char* start = strstr(rest, "from") + 5;
            char* end = strstr(rest, "to") + 3;
            start = trim_str(start);
            end = trim_str(end);
            int from = atoi(start);
            int to = atoi(end);
            for(int i=from; i<=to; i++) {
                char var[20];
                sprintf(var, "%d", i);
                var_set("loop_index", var);
                if(debug_mode) printf("LOOP: %d\n", i);
            }
        }
        return;
    }
    
    if(strstr(line, "func") == line) {
        char* rest = line + 5;
        rest = trim_str(rest);
        char* name = strtok(rest, "(");
        char* code = strtok(NULL, ")");
        if(name && code) {
            register_func(name, code);
            if(debug_mode) printf("FUNC REGISTERED: %s\n", name);
        }
        return;
    }
    
    if(strstr(line, "call") == line) {
        char* rest = line + 5;
        rest = trim_str(rest);
        char* name = strtok(rest, "(");
        char* args_str = strtok(NULL, ")");
        if(name && args_str) {
            char* args[30];
            int arg_count = 0;
            char* arg = strtok(args_str, ",");
            while(arg && arg_count < 30) {
                args[arg_count++] = trim_str(arg);
                arg = strtok(NULL, ",");
            }
            char* result = call_func(name, args, arg_count);
            if(result) {
                if(debug_mode) printf("FUNC CALL: %s => %s\n", name, result);
            }
        }
        return;
    }
    
    if(strstr(line, "ret") == line) {
        char* val = line + 4;
        val = trim_str(val);
        var_set("return_value", val);
        if(debug_mode) printf("RETURN: %s\n", val);
        return;
    }
    
    if(strstr(line, "fse") == line) {
        char* name = line + 4;
        name = trim_str(name);
        if(debug_mode) printf("STRUCT DEFINED: %s\n", name);
        return;
    }
    
    if(strstr(line, "try") == line) {
        if(setjmp(error_jmp) == 0) {
            if(debug_mode) printf("TRY BLOCK START\n");
        }
        return;
    }
    
    if(strstr(line, "catch") == line) {
        char* e = line + 6;
        e = trim_str(e);
        printf("CATCH ERROR: %s\n", e);
        return;
    }
    
    if(strstr(line, "?") && strstr(line, ":")) {
        char* cond_part = strtok(line, "?");
        char* true_part = strtok(NULL, ":");
        char* false_part = strtok(NULL, "");
        if(cond_part && true_part && false_part) {
            cond_part = trim_str(cond_part);
            true_part = trim_str(true_part);
            false_part = trim_str(false_part);
            char* cond_value = var_get(cond_part);
            if(cond_value && strcmp(cond_value, "true") == 0) {
                execute_line(true_part);
            } else {
                execute_line(false_part);
            }
        }
        return;
    }
    
    if(strstr(line, "secure") == line) {
        secure_mode = 1;
        if(debug_mode) printf("SECURE MODE ENABLED\n");
        return;
    }
    
    if(strstr(line, "debug") == line) {
        debug_mode = 1;
        if(debug_mode) printf("DEBUG MODE ENABLED\n");
        return;
    }
    
    if(strstr(line, "verbose") == line) {
        verbose_mode = 1;
        if(verbose_mode) printf("VERBOSE MODE ENABLED\n");
        return;
    }
    
    if(strstr(line, "export") == line) {
        var_export();
        return;
    }
    
    if(strstr(line, "encrypt") == line) {
        char* rest = line + 8;
        rest = trim_str(rest);
        char* data = strtok(rest, ",");
        char* key = strtok(NULL, ",");
        if(data && key) {
            data = trim_str(data);
            key = trim_str(key);
            char* encrypted = encrypt_xor(data, key);
            var_set("encrypted_data", encrypted);
            if(debug_mode) printf("ENCRYPTED: %s\n", encrypted);
        }
        return;
    }
    
    if(strstr(line, "decrypt") == line) {
        char* rest = line + 8;
        rest = trim_str(rest);
        char* data = strtok(rest, ",");
        char* key = strtok(NULL, ",");
        if(data && key) {
            data = trim_str(data);
            key = trim_str(key);
            char* decrypted = decrypt_xor(data, key);
            var_set("decrypted_data", decrypted);
            if(debug_mode) printf("DECRYPTED: %s\n", decrypted);
        }
        return;
    }
    
    if(strstr(line, "genkey") == line) {
        char* rest = line + 7;
        rest = trim_str(rest);
        int len = atoi(rest);
        if(len <= 0) len = 256;
        char* key = generate_xor_key(len);
        var_set("generated_key", key);
        printf("GENERATED KEY: %s\n", key);
        return;
    }
    
    if(strstr(line, "system") == line) {
        char* cmd = line + 7;
        cmd = trim_str(cmd);
        system(cmd);
        return;
    }
    
    if(strstr(line, "include") == line) {
        char* file = line + 8;
        file = trim_str(file);
        if(file[0] == '"' || file[0] == '\'') {
            file++;
            file[strlen(file)-1] = 0;
        }
        if(file_exists(file)) {
            execute_file(file, secure_mode);
        } else {
            printf("INCLUDE FILE NOT FOUND: %s\n", file);
        }
        return;
    }
    
    if(strstr(line, "thread") == line) {
        char* rest = line + 7;
        rest = trim_str(rest);
        if(debug_mode) printf("THREAD CREATED: %s\n", rest);
        return;
    }
    
    if(strstr(line, "hack") == line) {
        char* rest = line + 5;
        rest = trim_str(rest);
        printf("HACKING TOOL: %s\n", rest);
        printf("WARNING: USE RESPONSIBLY\n");
        return;
    }
    
    if(strstr(line, "memory") == line) {
        char* rest = line + 7;
        rest = trim_str(rest);
        printf("MEMORY OPERATION: %s\n", rest);
        return;
    }
    
    if(strstr(line, "network") == line) {
        char* rest = line + 8;
        rest = trim_str(rest);
        printf("NETWORK OPERATION: %s\n", rest);
        return;
    }
}

void execute_file(char* file, int secure) {
    secure_mode = secure;
    current_file = file;
    char* code = read_file(file);
    if(!code) {
        cws_error("FILE NOT FOUND", 0);
        return;
    }
    
    line_number = 0;
    char* line = strtok(code, "\n");
    while(line) {
        line_number++;
        line = trim_str(line);
        if(line && line[0] != 0) {
            execute_line(line);
        }
        line = strtok(NULL, "\n");
    }
    
    free(code);
}

void execute_secure_file(char* file, char* key) {
    secure_mode = 1;
    char* code = read_file(file);
    if(!code) {
        cws_error("FILE NOT FOUND", 0);
        return;
    }
    char* decrypted = decrypt_xor(code, key);
    char tmp_file[] = "/tmp/cws_secure_XXXXXX.cws";
    int fd = mkstemp(tmp_file);
    write_file(tmp_file, decrypted);
    execute_file(tmp_file, 1);
    unlink(tmp_file);
    free(code);
    free(decrypted);
}

void execute_encrypted_file(char* file, char* key) {
    char* code = read_file(file);
    if(!code) {
        cws_error("FILE NOT FOUND", 0);
        return;
    }
    char* decrypted = decrypt_xor(code, key);
    char tmp_file[] = "/tmp/cws_decrypt_XXXXXX.cws";
    int fd = mkstemp(tmp_file);
    write_file(tmp_file, decrypted);
    execute_file(tmp_file, 0);
    unlink(tmp_file);
    free(code);
    free(decrypted);
}

void build_file(char* file, char* output) {
    char* code = read_file(file);
    if(!code) {
        cws_error("FILE NOT FOUND", 0);
        return;
    }
    
    char header[MAX_CODE];
    sprintf(header, 
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <time.h>\n"
        "#include <unistd.h>\n"
        "\n"
        "int main() {\n"
        "    printf(\"CWS F1 BUILD\\n\");\n"
        "    printf(\"CWS ENTERPRISE EDITION\\n\");\n"
    );
    
    char* full = malloc(strlen(header) + strlen(code) + 1000);
    sprintf(full, "%s%s\n    return 0;\n}\n", header, code);
    
    char cmd[2048];
    sprintf(cmd, "clang -O3 -o %s -x c - <<'EOF'\n%s\nEOF\n", output, full);
    system(cmd);
    
    printf("BUILD COMPLETE: %s\n", output);
    free(code);
    free(full);
}

void build_file_decrypted(char* code, char* output) {
    char header[MAX_CODE];
    sprintf(header, 
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <time.h>\n"
        "#include <unistd.h>\n"
        "\n"
        "int main() {\n"
        "    printf(\"CWS F1 SECURE BUILD\\n\");\n"
        "    printf(\"CWS ENTERPRISE EDITION\\n\");\n"
    );
    
    char* full = malloc(strlen(header) + strlen(code) + 1000);
    sprintf(full, "%s%s\n    return 0;\n}\n", header, code);
    
    char cmd[2048];
    sprintf(cmd, "clang -O3 -o %s -x c - <<'EOF'\n%s\nEOF\n", output, full);
    system(cmd);
    
    printf("SECURE BUILD COMPLETE: %s\n", output);
    free(full);
}

void build_secure_file(char* file, char* output, char* key) {
    char* code = read_file(file);
    if(!code) {
        cws_error("FILE NOT FOUND", 0);
        return;
    }
    char* decrypted = decrypt_xor(code, key);
    build_file_decrypted(decrypted, output);
    free(code);
    free(decrypted);
}

void show_help() {
    printf("CWS ENTERPRISE EDITION v%s\n", VERSION);
    printf("LANGUAGE OF THE STRONG\n");
    printf("\n");
    printf("COMMANDS:\n");
    printf("  cws run file.cws                 EXECUTE FILE\n");
    printf("  cws run --secure file.cws        EXECUTE IN SECURE MODE\n");
    printf("  cws run -k key file.enc          EXECUTE ENCRYPTED FILE\n");
    printf("  cws build file.cws -o out        BUILD EXECUTABLE\n");
    printf("  cws build --secure file.cws -o out BUILD SECURE EXECUTABLE\n");
    printf("  cws encrypt file.cws -o out -k key ENCRYPT FILE\n");
    printf("  cws decrypt file.enc -k key      DECRYPT FILE\n");
    printf("  cws --version                    SHOW VERSION\n");
    printf("  cws --help                       SHOW HELP\n");
    printf("  cws clean                        CLEAN ALL VARIABLES\n");
    printf("\n");
    printf("KEYWORDS:\n");
    printf("  pef   - VARIABLE (pef name ? value)\n");
    printf("  pef ??- SECURE VARIABLE\n");
    printf("  pef ???- ENCRYPTED VARIABLE\n");
    printf("  cos   - PRINT\n");
    printf("  wso   - LOOP (wso from X to Y)\n");
    printf("  func  - FUNCTION\n");
    printf("  call  - CALL FUNCTION\n");
    printf("  ret   - RETURN\n");
    printf("  fse   - STRUCT\n");
    printf("  cso   - IMPORT MODULE\n");
    printf("  try   - TRY BLOCK\n");
    printf("  catch - CATCH ERROR\n");
    printf("  ? :   - CONDITIONAL\n");
    printf("  secure- SECURE MODE\n");
    printf("  debug - DEBUG MODE\n");
    printf("  verbose- VERBOSE MODE\n");
    printf("  export- EXPORT VARIABLES\n");
    printf("  encrypt- ENCRYPT DATA\n");
    printf("  decrypt- DECRYPT DATA\n");
    printf("  genkey- GENERATE KEY\n");
    printf("  system- SYSTEM COMMAND\n");
    printf("  include- INCLUDE FILE\n");
    printf("  thread- CREATE THREAD\n");
    printf("  hack  - HACKING TOOL\n");
    printf("  memory- MEMORY OPERATION\n");
    printf("  network- NETWORK OPERATION\n");
}

void show_version() {
    printf("CWS v%s\n", VERSION);
    printf("BUILD: %s\n", BUILD);
    printf("LANGUAGE OF THE STRONG\n");
    printf("NO COMMENTS. NO WEAKNESS. NO LIMITS.\n");
}
