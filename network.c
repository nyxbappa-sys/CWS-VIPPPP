#include "core.h"

int cws_socket_create() {
    return socket(AF_INET, SOCK_STREAM, 0);
}

int cws_socket_connect(int sock, char* host, int port) {
    struct hostent* server = gethostbyname(host);
    if(!server) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
    addr.sin_port = htons(port);
    return connect(sock, (struct sockaddr*)&addr, sizeof(addr));
}

int cws_socket_bind(int sock, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    return bind(sock, (struct sockaddr*)&addr, sizeof(addr));
}

int cws_socket_listen(int sock, int backlog) {
    return listen(sock, backlog);
}

int cws_socket_accept(int sock) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    return accept(sock, (struct sockaddr*)&addr, &len);
}

int cws_socket_send(int sock, char* data) {
    return send(sock, data, strlen(data), 0);
}

int cws_socket_recv(int sock, char* buffer, int size) {
    return recv(sock, buffer, size, 0);
}

void cws_socket_close(int sock) {
    close(sock);
}
