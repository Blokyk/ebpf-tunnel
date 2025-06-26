// #include "connect.c"

#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <asm-generic/socket.h>
#include <linux/in.h>
#include <linux/netfilter_ipv4.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <threads.h>
#include <unistd.h>

#include "utils.h"

#define TUNNEL_PORT 18000
#define PROXY_HOST "127.0.0.1"
#define PROXY_PORT 8080

#define TUNNEL_BUFF_SIZE 4098

// Maximum length of the string representation of a (16-bit) port, including terminating \0
#define INET_PORTSTRLEN 6

bool send_conn_req(int conn_fd, int proxy_fd) {
    struct sockaddr_in original_dst = get_original_dst(conn_fd);
    char *original_addr = inet_ntoa(original_dst.sin_addr);
    in_port_t original_port = ntohs(original_dst.sin_port);

    static const char connect_req_template[] =
        "CONNECT %1$s:%2$d HTTP/1.1\r\n"
        "Host: %1$s:%2$d\r\n"
        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        "\r\n";

    static char connect_req[
        sizeof(connect_req_template)+
        (INET_ADDRSTRLEN-1)*2+
        (INET_PORTSTRLEN-1)*2+
        1 // for '\0'
    ];

    int req_len = snprintf(connect_req, sizeof(connect_req), connect_req_template, original_addr, original_port);

    if (!send_exactly(proxy_fd, connect_req, req_len)) {
        perror("Couldn't send initial connection request to the proxy");
        return false;
    }

    return true;
}

bool confirm_handshake(int proxy_fd) {
    int res;

    static char recv_buf[sizeof("HTTP/1.1 XXX")];

    if (!recv_exactly(proxy_fd, recv_buf, sizeof(recv_buf))) {
        perror("Couldn't read a full answer from the proxy");
        return false;
    }

    int status_code;
    if (sscanf(recv_buf, "HTTP/1.1 %d", &status_code) < 1) {
        fprintf(stderr, "Malformed HTTP response (begins with '%s')\n", recv_buf);
        return false;
    }

    if (status_code != 200)
        fprintf(stderr, "Handshake failed: got status code 200, got %d\n", status_code);

    discard_http_resp(proxy_fd);

    return status_code == 200;
}

struct fd_pair { int src_fd; int dst_fd; };
int join_fds(void *arg) {
    struct fd_pair *pair = arg;
    int src_fd = pair->src_fd, dst_fd = pair->dst_fd;
    do {
        char buf[TUNNEL_BUFF_SIZE];
        ssize_t available = read(src_fd, buf, sizeof(buf));

        // if we couldn't read anymore
        if (available <= 0)
            break;

        trace("[%d -> %d] read %zd bytes", src_fd, dst_fd, available);

        // if we couldn't write enough bytes
        if (!send_exactly(dst_fd, buf, available)) {
            // perror("write_exactly()")
            break;
        }

        trace("[%d -> %d] transferred %zd bytes", src_fd, dst_fd, available);
    } while(1);

    debug("shutdown fd %d -> fd %d", src_fd, dst_fd);
    // we don't want to completely close the socket, just this direction but not the others
    shutdown(src_fd, SHUT_RD); // we won't read from the src anymore
    shutdown(dst_fd, SHUT_WR); // we won't write to the dst anymore

    return 0;
}

void handle_connection(int conn_fd) {
    int res;

    trace("Opening socket to real proxy @ %s:%d for child %d\n", PROXY_HOST, PROXY_PORT, getpid());

    // yes, we do need to open a new socket for each child (see #9)
    int proxy_fd = open_connection(PROXY_HOST, PROXY_PORT);
    if (proxy_fd < 0) {
        fprintf(stderr, "Couldn't open connection to real proxy\n");
        exit(EXIT_FAILURE);
    }

    if (!send_conn_req(conn_fd, proxy_fd))
        exit(ECOMM);

    trace("Sent connection request to proxy");

    if (!confirm_handshake(proxy_fd))
        exit(ECOMM);

    trace("Got valid response from proxy, fully connected now");

    thrd_t conn_to_proxy_thread;
    struct fd_pair conn_to_proxy_pair = { conn_fd, proxy_fd };
    thrd_create(&conn_to_proxy_thread, &join_fds, &conn_to_proxy_pair);

    thrd_t proxy_to_conn_thread;
    struct fd_pair proxy_to_conn_pair = { proxy_fd, conn_fd };
    thrd_create(&proxy_to_conn_thread, &join_fds, &proxy_to_conn_pair);

    thrd_join(conn_to_proxy_thread, &res);
    thrd_join(proxy_to_conn_thread, &res);
}

int main(void) {
    int res;

    // write(2) and read(2) send a SIGPIPE error by default
    // when called on a closed socket, but we'd like to handle
    // that directly in the code, not with a signal handler
    // we could use recv/send's MSG_NOSIGNAL flag, but this
    // avoids having to deal with that everywhere else
    struct sigaction sigact_ign = { .sa_handler=SIG_IGN };
    sigaction(SIGPIPE, &sigact_ign, NULL);

    debug("Opening tunnel on port %d\n", TUNNEL_PORT);

    int listening_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listening_fd == 0) {
        perror("Couldn't acquire a socket for tunnel");
        exit(EXIT_FAILURE);
    }

    // #ifndef DEBUG
        bool reuse_addr = true;
        setsockopt(listening_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
    // #endif // DEBUG

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(TUNNEL_PORT),
        .sin_addr   = INADDR_ANY,
        .sin_zero   = {0},
    };
    socklen_t addr_len = sizeof(addr);

    res = bind(listening_fd, (struct sockaddr*)&addr, addr_len);
    if (res != 0) {
        perror("Couldn't bind tunnel");
        exit(EXIT_FAILURE);
    }

    trace("Tunnel bound to %d", TUNNEL_PORT);

    res = listen(listening_fd, 128);
    if (res != 0) {
        perror("Couldn't let tunnel listen");
        exit(EXIT_FAILURE);
    }

    trace("Tunnel listening on port %d", TUNNEL_PORT);

    int conn_fd;
    while ((conn_fd = accept(listening_fd, (struct sockaddr*)&addr, &addr_len))) {
        // if (fork() == 0)
            handle_connection(conn_fd);
    }

    perror("Intermediate proxy couldn't accept()");
    return 1;
}