/*
 * Minimal multi-port HTTP responder for the local benchmark.
 *
 * One epoll loop owns many listening ports and answers the first request with
 * a fixed HTTP/1.1 response. It is deliberately tiny: no files, no logging per
 * connection, no TLS. The goal is to make the lab target cheap enough that a
 * ZBanner/stateful benchmark is not dominated by the target process.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTENER_FLAG (1ull << 63)
#define MAX_EVENTS    4096
#define BACKLOG       256

static int hold_mode = 0;

static const char RESPONSE[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 2\r\n"
    "Connection: close\r\n"
    "\r\n"
    "OK";


static int make_listener(unsigned port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, BACKLOG) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void close_client(int epfd, int fd) {
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: lab-http START_PORT END_PORT [--hold]\n");
        return 2;
    }
    if (argc == 4 && strcmp(argv[3], "--hold") == 0)
        hold_mode = 1;

    unsigned first = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned last  = (unsigned)strtoul(argv[2], NULL, 10);
    if (first == 0 || last < first || last > 65535) {
        fprintf(stderr, "invalid port range %u-%u\n", first, last);
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        perror("epoll_create1");
        return 1;
    }

    unsigned listeners = 0;
    for (unsigned port = first; port <= last; port++) {
        int fd = make_listener(port);
        if (fd < 0) {
            fprintf(stderr, "listen %u: %s\n", port, strerror(errno));
            return 1;
        }
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events   = EPOLLIN;
        ev.data.u64 = ((uint64_t)(unsigned)fd) | LISTENER_FLAG;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            perror("epoll_ctl listener");
            return 1;
        }
        listeners++;
    }

    printf("lab-http listening on %u-%u (%u sockets)%s\n", first, last,
           listeners, hold_mode ? " [hold]" : "");
    fflush(stdout);

    struct epoll_event events[MAX_EVENTS];
    for (;;) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            return 1;
        }

        for (int i = 0; i < n; i++) {
            uint64_t tag = events[i].data.u64;
            int      fd  = (int)(tag & ~LISTENER_FLAG);

            if (tag & LISTENER_FLAG) {
                for (;;) {
                    int client = accept4(fd, NULL, NULL,
                                         SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (client < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        if (errno == EINTR || errno == ECONNABORTED)
                            continue;
                        break;
                    }


                    int one = 1;
                    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one,
                               sizeof(one));

                    struct epoll_event cev;
                    memset(&cev, 0, sizeof(cev));
                    cev.events   = EPOLLIN | EPOLLRDHUP | EPOLLERR;
                    cev.data.u64 = (uint64_t)(unsigned)client;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, client, &cev) < 0) {
                        close(client);
                    }
                }
                continue;
            }

            /* Client: wait for the request/probe payload, then answer once. */
            unsigned char buf[2048];
            ssize_t       got = recv(fd, buf, sizeof(buf), 0);
            if (got > 0) {
                if (hold_mode) {
                    /* Keep the accepted socket open without answering so the
                     * scanner's TCB stays alive. The process is killed by the
                     * lab when the stateful case ends. */
                    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                } else {
                    (void)send(fd, RESPONSE, sizeof(RESPONSE) - 1,
                               MSG_NOSIGNAL);
                    close_client(epfd, fd);
                }
            } else if (got == 0) {
                close_client(epfd, fd);
            } else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                       errno != EINTR) {
                close_client(epfd, fd);
            }
        }
    }
}
