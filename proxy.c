#include "connect.c"

#include <cstdlib>
#include <linux/in.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#define PROXY_PORT 18000
#define REAL_PROXY_HOST "127.0.0.1"
#define REAL_PROXY_PORT 8080
#define CONNECT_TIMEOUT 5

int main(void) {
    int res;

    printf("Connecting to real proxy @ %s:%d\n", REAL_PROXY_HOST, REAL_PROXY_PORT);

    int real_proxy_fd = open_connection(REAL_PROXY_HOST, REAL_PROXY_PORT);
    if (real_proxy_fd < 0) {
        perror("Couldn't open connection to real proxy");
        exit(EXIT_FAILURE);
    }

    res = begin_http_relay(real_proxy_fd);
    if (res != START_OK) {
        perror("Couldn't connect properly to real proxy");
        exit(EXIT_FAILURE);
    }

    printf("Opening tunnel on port %d\n", PROXY_PORT);

    while (1) {
        int tunnel_fd = accept_connection(PROXY_PORT);
    }

    // int listening_fd = socket(AF_INET, SOCK_STREAM, 0);
    // if (listening_fd == 0) {
    //     perror("Could not acquire a socket for intermediate proxy");
    //     exit(EXIT_FAILURE);
    // }

    // struct sockaddr_in addr = {
    //     .sin_family = AF_INET,
    //     .sin_port   = htons(PROXY_PORT),
    //     .sin_addr   = INADDR_LOOPBACK,
    //     .sin_zero   = {0},
    // };
    // socklen_t addr_len = sizeof(addr);

    // res = bind(listening_fd, (struct sockaddr*)&addr, addr_len);
    // if (res != 0) {
    //     perror("Couldn't not bind intermediate proxy");
    //     exit(EXIT_FAILURE);
    // }

    // res = listen(listening_fd, 128);
    // if (res != 0) {
    //     perror("Couldn't let intermediate proxy listen");
    //     exit(EXIT_FAILURE);
    // }

    // char buf[1024];
    // int conn_fd;
    // while ((conn_fd = accept(listening_fd, (struct sockaddr*)&addr, &addr_len))) {

    // }

    perror("Intermediate proxy couldn't accept()");
    return 1;
}