#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>

#ifdef TRACE
#define DEBUG
#define trace(s, ...) fprintf(stderr, s "\n" __VA_OPT__(,) __VA_ARGS__)
#else
#define trace(...)
#endif // TRACE

#ifdef DEBUG
#define debug(s, ...) fprintf(stderr, s "\n" __VA_OPT__(,) __VA_ARGS__)
#else
#define debug(...)
#endif // DEBUG

#define perrorf(s, ...) fprintf(stderr, s ": %s\n", __VA_ARGS__ __VA_OPT__(,) strerror(errno))

int resolve(const char *host, struct sockaddr_in *addr);
int open_connection(const char *host, uint16_t port);
struct sockaddr_in get_original_dst(int conn_fd);

bool send_exactly(int fd, void *buf, size_t buflen);
bool recv_exactly(int fd, void *buf, size_t buflen);

/// Reads the given socket until a \r\n\r\n (double CRLF) sequence
void discard_http_resp(int fd);