#include "target-rangeport.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "target.h"
#include "target-set.h"
#include "target-rangev4.h"

#include "../util-out/logger.h"
#include "../util-misc/misc.h"

/*
 * Ports are 16-bit numbers ([0..65535], but different
 * transports (TCP, UDP, SCTP, Other IP protocol num) are distinct port ranges.
 * Thus, we instead of three 64k and one 0xFF ranges we could instead treat
 * this internally together.
 * We can expand this range to include other
 * things we scan for, such as ICMP pings or ARP requests.
 */
#define PORT_SPEC    65535
#define TCP_START    0
#define TCP_LAST     (TCP_START + PORT_SPEC)
#define UDP_START    (TCP_LAST + 1)
#define UDP_LAST     (UDP_START + PORT_SPEC)
#define SCTP_START   (UDP_LAST + 1)
#define SCTP_LAST    (SCTP_START + PORT_SPEC)
#define OPROTO_START (SCTP_LAST + 1)
#define OPROTO_LAST  (OPROTO_START + PORT_SPEC)

/** Use this when adding TCP ports, to avoid the comoplication of how
 * ports are stored */
void rangelist_add_range_tcp(struct RangeList *targets, unsigned begin,
                             unsigned end) {
    rangelist_add_range(targets, TCP_START + begin, TCP_START + end);
}

/** Use this when adding UDP ports, to avoid the comoplication of how
 * ports are stored */
void rangelist_add_range_udp(struct RangeList *targets, unsigned begin,
                             unsigned end) {
    rangelist_add_range(targets, UDP_START + begin, UDP_START + end);
}

/*
 * Parse one port number. The previous code cast strtoul() straight to
 * `unsigned` and only range-checked afterwards, so on LP64 a value like
 * 4294967296 truncated to 0 and silently passed as port 0. Check the
 * 64-bit result (and ERANGE) first instead.
 */
static int parse_one_port(char **pstr, unsigned *port) {
    char         *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(*pstr, &end, 0);
    if (end == *pstr || errno == ERANGE || value > PORT_SPEC)
        return -1;

    *pstr = end;
    *port = (unsigned)value;
    return 0;
}

/***************************************************************************
 * This returns a character pointer where parsing ends so that it can
 * handle multiple stuff on the same line
 ***************************************************************************/
const char *rangelist_parse_ports(struct RangeList *ports, const char *string,
                                  unsigned *is_error, unsigned proto_offset) {
    char    *p   = (char *)string;
    unsigned tmp = 0;

    if (is_error == NULL)
        is_error = &tmp;

    *is_error = 0;
    while (*p) {
        unsigned port;
        unsigned end;

        /* skip whitespace */
        while (*p && isspace(*p & 0xFF))
            p++;

        /* end at comment */
        if (*p == 0 || *p == '#')
            break;

        /* special processing. Nmap allows ports to be prefixed with a
         * characters to clarify TCP, UDP, or SCTP */
        if (isalpha(*p & 0xFF) && p[1] == ':') {
            switch (*p) {
                case 'T':
                case 't':
                    proto_offset = TCP_START;
                    break;
                case 'U':
                case 'u':
                    proto_offset = UDP_START;
                    break;
                case 'S':
                case 's':
                    proto_offset = SCTP_START;
                    break;
                case 'O':
                case 'o':
                    proto_offset = OPROTO_START;
                    break;
                default:
                    LOG(LEVEL_ERROR, "bad port character = %c\n", p[0]);
                    *is_error = 1;
                    return p;
            }
            p += 2;
        }

        /*
         * Get the start of the range.
         */
        if (p[0] == '-') {
            /* nmap style port range spec meaning starting with 0 */
            port = 1;
        } else if (parse_one_port(&p, &port) != 0) {
            if (!isdigit(p[0] & 0xFF))
                break;
            LOG(LEVEL_ERROR, "bad port number: %s\n", string);
            *is_error = 2;
            return p;
        }

        /*
         * Get the end of the range
         */
        if (*p == '-') {
            p++;
            if (!isdigit(*p)) {
                /* nmap style range spec meaning end with 65535 */
                end = PORT_SPEC;
            } else if (parse_one_port(&p, &end) != 0) {
                LOG(LEVEL_ERROR, "bad port number: %s\n", string);
                *is_error = 2;
                return p;
            }
        } else
            end = port;

        /* Check for out-of-range */
        if (port > PORT_SPEC || end > PORT_SPEC || end < port) {
            LOG(LEVEL_ERROR, "bad port range: %s\n", string);
            *is_error = 2;
            return p;
        }

        /* Add to our list */
        rangelist_add_range(ports, port + proto_offset, end + proto_offset);

        /* skip trailing whitespace */
        while (*p && isspace(*p & 0xFF))
            p++;

        /* Now get the next port/range if there is one */
        if (*p != ',')
            break;
        p++;
    }

    return p;
}

void rangeport_println(const struct RangeList *ports, FILE *fp) {
    /* Disable comma generation for the first element */
    unsigned i = 0;
    unsigned l = 0;
    for (i = 0; i < ports->list_len; i++) {
        struct Range range = ports->list[i];
        do {
            struct Range rrange = range;
            unsigned     done   = 0;
            if (l) {
                fprintf(fp, ",");
            } else {
                fprintf(fp, "port = ");
            }
            l = 1;
            if (rrange.begin >= OPROTO_START) {
                rrange.begin -= OPROTO_START;
                rrange.end -= OPROTO_START;
                fprintf(fp, "O:");
                done = 1;
            } else if (rrange.begin >= SCTP_START) {
                rrange.begin -= SCTP_START;
                rrange.end -= SCTP_START;
                fprintf(fp, "S:");
                range.begin = OPROTO_START;
            } else if (rrange.begin >= UDP_START) {
                rrange.begin -= UDP_START;
                rrange.end -= UDP_START;
                fprintf(fp, "U:");
                range.begin = SCTP_START;
            } else {
                range.begin = UDP_START;
            }

            rrange.end = min(rrange.end, 65535);
            if (rrange.begin == rrange.end)
                fprintf(fp, "%u", rrange.begin);
            else
                fprintf(fp, "%u-%u", rrange.begin, rrange.end);

            if (done)
                break;

        } while (range.begin <= range.end);
    }

    if (l)
        fprintf(fp, "\n");
}

void rangeport_print(const struct RangeList *ports, FILE *fp,
                     unsigned default_ipproto) {
    /* print all ports */
    unsigned i;
    for (i = 0; i < ports->list_len; i++) {
        unsigned proto;
        int      begin = ports->list[i].begin;
        int      end   = ports->list[i].end;

        if (TCP_START <= begin && begin < UDP_START) {
            proto = IP_PROTO_TCP;
            begin -= TCP_START;
            end -= TCP_START;
        } else if (UDP_START <= begin && begin < SCTP_START) {
            proto = IP_PROTO_UDP;
            begin -= UDP_START;
            end -= UDP_START;
        } else if (SCTP_START <= begin && begin < OPROTO_START) {
            proto = IP_PROTO_SCTP;
            begin -= SCTP_START;
            end -= SCTP_START;
        } else {
            proto = IP_PROTO_Other;
            begin -= OPROTO_START;
            end -= OPROTO_START;
        }

        /* print comma between ports, but not for first port */
        if (i)
            fprintf(fp, ",");

        /**
         * Print either one number for a single port, or two numbers for a range
         */
        if (default_ipproto != proto) {
            proto = default_ipproto;
            switch (proto) {
                case IP_PROTO_TCP:
                    fprintf(fp, "T:");
                    break;
                case IP_PROTO_UDP:
                    fprintf(fp, "U:");
                    break;
                case IP_PROTO_SCTP:
                    fprintf(fp, "S:");
                    break;
                default:
                    fprintf(fp, "O:");
                    break;
            }
        }
        fprintf(fp, "%u", begin);
        if (end > begin)
            fprintf(fp, "-%u", end);
    }
}

uint16_t get_actual_proto_port(unsigned *raw_port) {
    if (*raw_port <= TCP_LAST)
        return IP_PROTO_TCP;
    else if (*raw_port <= UDP_LAST) {
        *raw_port &= 0xFFFF;
        return IP_PROTO_UDP;
    } else if (*raw_port <= SCTP_LAST) {
        *raw_port &= 0xFFFF;
        return IP_PROTO_SCTP;
    } else if (*raw_port <= OPROTO_LAST) {
        *raw_port &= 0xFFFF;
        return IP_PROTO_Other;
    } else {
        return IP_PROTO_Other;
    }
}

unsigned get_complex_port(uint16_t port, unsigned ip_proto) {
    if (ip_proto == IP_PROTO_TCP)
        return (unsigned)port + TCP_START;
    else if (ip_proto == IP_PROTO_UDP)
        return (unsigned)port + UDP_START;
    else if (ip_proto == IP_PROTO_SCTP)
        return (unsigned)port + SCTP_START;
    else
        return ~0;
}

int rangesport_selftest() {
    TargetSet targets = {.ipv4 = {0}, .ipv6 = {0}, .ports = {0}};

    unsigned err;
    int      line;

    /*Positive Samples*/
    line = __LINE__;
    err  = 0;
    rangelist_parse_ports(&targets.ports, "8080,-80,100-120", &err, 0);
    if (err)
        goto fail;

    line = __LINE__;
    err  = 0;
    rangelist_parse_ports(&targets.ports, "t:120,u:33-66", &err, 0);
    if (err)
        goto fail;

    line = __LINE__;
    err  = 0;
    rangelist_parse_ports(&targets.ports, "22,s:8080-9090,o:9090-10000", &err,
                          0);
    if (err)
        goto fail;

    return 0;

fail:
    LOG(LEVEL_ERROR, "(%s) selftest fail, line=%d\n", __func__, line);
    return 1;
}