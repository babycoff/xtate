#ifndef TEMPL_TCP_H
#define TEMPL_TCP_H

#include <stdio.h>

#include "templ-pkt.h"
#include "templ-opts.h"
#include "../target/target-ipaddress.h"

#define TCP_FLAG_CWR 0B10000000
#define TCP_FLAG_ECE 0B01000000
#define TCP_FLAG_URG 0B00100000
#define TCP_FLAG_ACK 0B00010000
#define TCP_FLAG_PSH 0B00001000
#define TCP_FLAG_RST 0B00000100
#define TCP_FLAG_SYN 0B00000010
#define TCP_FLAG_FIN 0B00000001

#define TCP_SEQNO(px, transport_offset)                                        \
    ((unsigned)(px)[(transport_offset) + 4] << 24 |                            \
     (unsigned)(px)[(transport_offset) + 5] << 16 |                            \
     (unsigned)(px)[(transport_offset) + 6] << 8 |                             \
     (unsigned)(px)[(transport_offset) + 7])
#define TCP_ACKNO(px, transport_offset)                                        \
    ((unsigned)(px)[(transport_offset) + 8] << 24 |                            \
     (unsigned)(px)[(transport_offset) + 9] << 16 |                            \
     (unsigned)(px)[(transport_offset) + 10] << 8 |                            \
     (unsigned)(px)[(transport_offset) + 11])
#define TCP_WIN(px, transport_offset)                                          \
    ((px)[(transport_offset) + 14] << 8 |                                      \
     (px)[(transport_offset) + 15]) /*calc TCP window size*/
#define TCP_FLAGS(px, transport_offset) ((px)[(transport_offset) + 13])
#define TCP_HAS_FLAG(px, transport_offset, flag)                               \
    ((TCP_FLAGS((px), (transport_offset)) & (flag)) == (flag))
#define TCP_FLAG_HAS(flag, test_flag) (((flag) & (test_flag)) == (test_flag))

/**
 * ref: https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
 */
#define TCP_OPT_TYPE_EOL        0 /*End of Option List*/
#define TCP_OPT_TYPE_NOP        1 /*No-Operation*/
#define TCP_OPT_TYPE_MSS        2
#define TCP_OPT_TYPE_WS         3 /*Window Scale*/
#define TCP_OPT_TYPE_SACK_PERM  4 /*SACK Permitted*/
#define TCP_OPT_TYPE_SACK       5
#define TCP_OPT_TYPE_ECHO       6
#define TCP_OPT_TYPE_ECHO_REPLY 7
#define TCP_OPT_TYPE_TS         8  /*Timestamps*/
#define TCP_OPT_TYPE_POCP       9  /*Partial Order Connection Permitted*/
#define TCP_OPT_TYPE_POSP       10 /*Partial Order Service Profile*/
#define TCP_OPT_TYPE_CC         11
#define TCP_OPT_TYPE_CCNEW      12
#define TCP_OPT_TYPE_CCECHO     13
#define TCP_OPT_TYPE_ACR        14 /*TCP Alternate Checksum Request*/
#define TCP_OPT_TYPE_ACD        15 /*TCP Alternate Checksum Data*/
#define TCP_OPT_TYPE_SKEETER    16
#define TCP_OPT_TYPE_BUBBA      17
#define TCP_OPT_TYPE_TCO        18 /*Trailer Checksum Option*/
#define TCP_OPT_TYPE_MD5        19 /*MD5 Signature Option*/
#define TCP_OPT_TYPE_SCPS       20 /*SCPS Capabilities*/
#define TCP_OPT_TYPE_SNA        21 /*Selective Negative Acknowledgements*/
#define TCP_OPT_TYPE_RECORD_BDR 22 /*Record Boundaries*/
#define TCP_OPT_TYPE_CORRUPT    23 /*Corruption experienced*/
#define TCP_OPT_TYPE_SNAP       24
#define TCP_OPT_TYPE_CF         26 /*TCP Compression Filter*/
#define TCP_OPT_TYPE_QSR        27 /*Quick-Start Response*/
/*User Timeout Option (also, other known unauthorized use)*/
#define TCP_OPT_TYPE_UTO        28
#define TCP_OPT_TYPE_AO         29 /*TCP Authentication Option (TCP-AO)*/
#define TCP_OPT_TYPE_MPTCP      30 /*Multipath TCP*/
#define TCP_OPT_TYPE_FOC        34 /*TCP Fast Open Cookie*/
#define TCP_OPT_TYPE_ENO        69 /*Encryption Negotiation (TCP-ENO)*/
/*RFC3692-style Experiment 1 (also improperly used for shipping products)*/
#define TCP_OPT_TYPE_EXP1       253
/*RFC3692-style Experiment 2 (also improperly used for shipping products) */
#define TCP_OPT_TYPE_EXP2       254

#define TCP_OPT_LEN_EOL        1
#define TCP_OPT_LEN_NOP        1
#define TCP_OPT_LEN_MSS        4
#define TCP_OPT_LEN_WS         3
#define TCP_OPT_LEN_ECHO       6
#define TCP_OPT_LEN_ECHO_REPLY 6
#define TCP_OPT_LEN_SACK_PERM  2
#define TCP_OPT_LEN_TS         10
#define TCP_OPT_LEN_POCP       2
#define TCP_OPT_LEN_POSP       3
#define TCP_OPT_LEN_ACR        3
#define TCP_OPT_LEN_TCO        3
#define TCP_OPT_LEN_MD5        18
#define TCP_OPT_LEN_QSR        8
#define TCP_OPT_LEN_UTO        4

#define TCP_DEFAULT_MSS    1460
#define TCP_DEFAULT_TSECHO 0x12345678

struct TcpOption {
    const unsigned char *buf;
    size_t               opt_len;
    /*raw_len = opt_len - opt_hdr (opt_hdr=kind(1)+len(1)=2)*/
    size_t               raw_len;
    unsigned             kind;
    bool                 is_found;
};

/**
 * Called during configuration, to apply all the various changes the
 * user asked for on the command-line, such as optioms like:
 * --tcp-mss 1460
 * --tcp-sackperm
 * --tcp-wscale 3
 */
void templ_tcp_apply_options(unsigned char **inout_buf, size_t *inout_length,
                             const TmplOpt *templ_opts);

/**
 * Set's the TCP "window" field in raw.
 */
void tcp_set_window(unsigned char *px, size_t px_length, unsigned window);

/**
 * Create a TCP packet containing a payload
 * @param ttl use default value in packet template if set to zero
 * @param win use default value in packet template if set to zero
 */
size_t tcp_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                              unsigned port_them, ipaddress ip_me,
                              unsigned port_me, unsigned seqno, unsigned ackno,
                              unsigned flags, unsigned ttl, unsigned win,
                              const unsigned char *payload,
                              size_t payload_length, unsigned char *px,
                              size_t px_length);

/**
 * This is a wrapped func that uses global_tmplset to create tcp packet.
 * @param ttl use default value in packet template if set to zero
 * @param win use default value in packet template if set to zero
 */
size_t tcp_create_packet(ipaddress ip_them, unsigned port_them, ipaddress ip_me,
                         unsigned port_me, unsigned seqno, unsigned ackno,
                         unsigned flags, unsigned ttl, unsigned win,
                         const unsigned char *payload, size_t payload_length,
                         unsigned char *px, size_t px_length);

/*Convert TCP flags into string*/
void tcp_flags_to_string(unsigned flag, char *string, size_t str_len);

/**
 * Search the TCP header's <options> field for the specified kind/type.
 * Typical kinds of options are MSS, window scale, SACK, timestamp.
 */
struct TcpOption tcp_find_opt(const unsigned char *buf, size_t length,
                              unsigned in_kind);

unsigned tcp_get_mss(const unsigned char *buf, size_t length, bool *is_found);

unsigned tcp_get_wscale(const unsigned char *buf, size_t length,
                        bool *is_found);

unsigned tcp_get_sackperm(const unsigned char *buf, size_t length,
                          bool *is_found);

int templ_tcp_selftest();

#endif
