#include "core.h"

int cws_process_exec(char* cmd) {
    return system(cmd);
}

int cws_process_fork() {
    return fork();
}

int cws_process_wait() {
    int status;
    wait(&status);
    return status;
}

void cws_process_exit(int code) {
    exit(code);
}

int cws_process_getpid() {
    return getpid();
}

int cws_process_getppid() {
    return getppid();
}
