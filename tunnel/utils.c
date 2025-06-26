#include "utils.h"

#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RECV_BUF_SIZE 1024

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

    // final send call without MSG_MORE to tell the OS we're done
    send(fd, buf, 0, 0);

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

void discard_http_resp(int fd) {
    char buf[RECV_BUF_SIZE];

    ssize_t bytes_read = 0;

    do {
        bytes_read = recv(fd, buf, RECV_BUF_SIZE, MSG_PEEK);

        char* crlf_pos = memmem(buf, bytes_read, "\r\n\r\n", 4);

        if (crlf_pos != NULL) {
            size_t crlf_offset = crlf_pos - buf;
            trace("discarded the last %ld bytes of http response", crlf_offset);
            // now that we've found the CRLF, just read everything up to and including it
            recv(fd, buf, crlf_offset + 4, 0);
            break;
        }

        // if we couldn't find it, just consume the buffer we just peeked at
        recv(fd, buf, bytes_read, 0); // note: we only read `bytes_read` bytes in case we since received more bytes that we couldn't look at
    } while (bytes_read > 0);
}