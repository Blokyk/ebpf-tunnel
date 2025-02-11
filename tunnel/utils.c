#include "utils.h"

#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* set of character for strspn() */
const char *digits    = "0123456789";
const char *dotdigits = "0123456789.";

int resolve(const char *host, struct sockaddr_in *addr) {
    if (strspn(host, dotdigits) == strlen(host)) {
        /* given by IPv4 address */
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = inet_addr(host);
    } else {
        trace("resolving host by name: %s\n", host);
        struct hostent *ent = gethostbyname(host);

        if (ent == NULL) {
            perrorf("Failed to resolve '%s'", host);
            return -1;
        }

        memcpy (&addr->sin_addr, ent->h_addr, ent->h_length);
        addr->sin_family = ent->h_addrtype;
        trace("resolved: %s = %s\n", host, inet_ntoa(addr->sin_addr));
    }
    return 0;                                   /* good */
}

int open_connection(const char *host, uint16_t port)
{
    int s;
    struct sockaddr_in saddr;

    /* resolve address of proxy or direct target */
    if (resolve(host, &saddr) < 0) {
        fprintf(stderr, "can't resolve hostname: %s\n", host);
        return -1;
    }
    saddr.sin_port = htons(port);

    debug("connecting to %s:%u\n", inet_ntoa(saddr.sin_addr), port);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        perrorf("Failed to connect to '%s'", host);
        exit(ECONNREFUSED);
    }
    return s;
}

struct sockaddr_in get_original_dst(int conn_fd) {
    int res;

    struct sockaddr_in addr = {0};
    socklen_t addrlen = sizeof(addr);

    res = getsockopt(
        conn_fd,
        SOL_IP,
        SO_ORIGINAL_DST,
        (struct sockaddr*)&addr,
        &addrlen
    );

    if (res != 0) {
        perror("getsockopt()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

bool send_exactly(int fd, void *buf, size_t buflen) {
    ssize_t written = 0;

    do {
        written = send(fd, buf, buflen, MSG_MORE);

        if (buflen != written)
            trace("write(fd:%d, len:%zd) = %zd", fd, buflen, written);

        buf += written;
        buflen -= written;
    } while (buflen != 0 && written > 0);

    return written != -1; // != -1 ?
}

bool recv_exactly(int fd, void *buf, size_t buflen) {
    return recv(fd, buf, buflen, MSG_WAITALL) != -1;
    // ssize_t bytes_read = 0;

    // do {
    //     bytes_read = read(fd, buf, buflen);

    //     if (buflen != bytes_read)
    //         trace("read(fd:%d, len:%zd) = %zd", fd, buflen, bytes_read);

    //     buf += bytes_read;
    //     buflen -= bytes_read;
    // } while (buflen != 0 && bytes_read > 0);

    // return bytes_read != -1; // != -1 ?
}