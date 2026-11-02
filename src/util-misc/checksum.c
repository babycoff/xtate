/*
    Calculates Internet checksums for protocols like TCP/IP.

    Author: Robert David Graham
    Copyright: 2020
    License: The MIT License (MIT)
    Dependencies: none

    Modified: Alvin Chen 2024
*/
#include "checksum.h"

#include <stdint.h>

#include "../target/target.h"
#include "../util-out/logger.h"

/**
 * Calculates the checksum over a buffer.
 * @param checksum
 *      The value of the pseudo-header checksum that this sum will be
 *      added to. This value must be calculated separately. This
 *      is the original value in 2s-complement. In other words,
 *      for TCP, which will be the integer value of the
 *      IP addresses, protocol number, and length field added together.
 * @param buf
 *      The buffer that we are checksumming, such as all the
 *      payload after an IPv4 or IPv6 header.
 */
static uint64_t _checksum_calculate(const void *vbuf, size_t length) {
    uint64_t             sum = 0;
    size_t               i;
    const unsigned char *buf = (const unsigned char *)vbuf;
    int                  is_remainder;

    /* If there is an odd number of bytes, then we handle the
     * last byte in a custom manner. */
    is_remainder = (length & 1);
    length &= (~1);

    /* Sum up all the 16-bit words in the packet */
    for (i = 0; i < length; i += 2) {
        sum += buf[i] << 8 | buf[i + 1];
    }

    /* If there is an odd number of bytes, then add the last
     * byte to the sum, in big-endian format as if there was
     * an additional trailing byte of zero. */
    if (is_remainder)
        sum += buf[length] << 8;

    /* Return the raw checksum. Note that this hasn't been
     * truncated to 16-bits yet or had the bits reversed. */
    return sum;
}

/**
 * After we sum up all the numbers involved, we must "fold" the upper
 * 16-bits back into the lower 16-bits. Since something like 0x1FFFF
 * will fold into 0x10000, we need to call a second fold operation
 * (obtaining 0x0001 in this example). In other words, we need to
 * keep folding until the result is 16-bits, but that never takes
 * more than two folds. After this, we need to take the 1s-complement,
 * which means reversing the bits so that 0 becomes 1 and 1 becomes 0.
 */
static unsigned _checksum_finish(uint64_t sum) {
    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);
    return (~sum) & 0xFFFF;
}

unsigned checksum_ipv4_upper(unsigned ip_src, unsigned ip_dst,
                             unsigned ip_proto, size_t payload_length,
                             const void *payload) {
    uint64_t             sum = 0;
    const unsigned char *buf = (const unsigned char *)payload;

    /**
     * Calculate the sum of the pseudo-header.
     * NOTE: that all these fields are assumed to be in host byte-order, not
     * big-endian. NOTE: the length of pseudo-header is even.
     * */
    sum += (ip_src >> 16) & 0xFFFF;
    sum += (ip_src >> 0) & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += (ip_dst >> 0) & 0xFFFF;
    sum += ip_proto;
    sum += (unsigned)payload_length;

    /**
     * Sum of upper-layer
     */
    sum += _checksum_calculate(buf, payload_length);

    /* Remove the existing checksum field from the calculation. */
    switch (ip_proto) {
        case IP_PROTO_HOPOPT: /*embedded ip header*/
            sum = _checksum_calculate(buf, payload_length);
            /* pretend the existing checksum field is zero */
            sum -= buf[10] << 8 | buf[11];
            break;
        case IP_PROTO_ICMP:
            sum = _checksum_calculate(buf, payload_length);
            sum -= buf[2] << 8 | buf[3];
            break;
        case IP_PROTO_IGMP: /* IGMP - group message - has no pseudo header */
            sum = _checksum_calculate(buf, payload_length);
            sum -= buf[2] << 8 | buf[3];
            break;
        case IP_PROTO_TCP:
            sum -= buf[16] << 8 | buf[17];
            break;
        case IP_PROTO_UDP:
            sum -= buf[6] << 8 | buf[7];
            break;
        default:
            return 0xFFFFFFFF;
    }

    /* fold and invert */
    return _checksum_finish(sum);
}

unsigned checksum_ipv6_upper(const unsigned char *ip_src,
                             const unsigned char *ip_dst, unsigned ip_proto,
                             size_t payload_length, const void *payload) {
    const unsigned char *buf = (const unsigned char *)payload;
    uint64_t             sum = 0;

    if (ip_src == NULL || ip_dst == NULL ||
        (payload == NULL && payload_length != 0))
        return 0xFFFFFFFF;

    /* The checksum field must be present before subtracting it. */
    if ((ip_proto == IP_PROTO_IPv6_ICMP && payload_length < 4) ||
        (ip_proto == IP_PROTO_TCP && payload_length < 18) ||
        (ip_proto == IP_PROTO_UDP && payload_length < 8))
        return 0xFFFFFFFF;

    /* Calculate the pseudo-header */
    sum += _checksum_calculate(ip_src, 16);
    sum += _checksum_calculate(ip_dst, 16);
    sum += (unsigned)payload_length;
    sum += ip_proto;

    /* Calculate the remainder of the checksum */
    sum += _checksum_calculate(payload, payload_length);

    /* Remove the existing checksum field. */
    switch (ip_proto) {
        case IP_PROTO_HOPOPT: /*embedded ip header*/
                              /*ipv6 header has no checksum*/
            return 0;
        case IP_PROTO_IPv6_ICMP:
            sum -= buf[2] << 8 | buf[3];
            break;
        case IP_PROTO_TCP:
            sum -= buf[16] << 8 | buf[17];
            break;
        case IP_PROTO_UDP:
            sum -= buf[6] << 8 | buf[7];
            break;
        default:
            return 0xFFFFFFFF;
    }

    /* fold and invert */
    return _checksum_finish(sum);
}

unsigned checksum_ipv4_header(const unsigned char *px, unsigned offset_ip,
                              unsigned max_offset) {
    unsigned header_length = (px[offset_ip] & 0xF) * 4;
    unsigned header_max    = offset_ip + header_length;
    uint64_t xsum          = 0;

    /* restrict border of header */
    if (max_offset < offset_ip + header_length) {
        LOG(LEVEL_ERROR, "(checksum_ipv4_header) wrong ip hdr len field.\n");
        header_max = max_offset;
    }

    xsum = _checksum_calculate(&px[offset_ip], header_max - offset_ip);

    /* fold and invert */
    return _checksum_finish(xsum);
}

/***************************************************************************
 ***************************************************************************/
unsigned checksum_ipv4_icmp(const unsigned char *px, unsigned offset_icmp,
                            size_t icmp_length) {
    uint64_t xsum = 0;

    xsum = _checksum_calculate(&px[offset_icmp], icmp_length);

    /* fold and invert */
    return _checksum_finish(xsum);
}

/***************************************************************************
 ***************************************************************************/
unsigned checksum_ipv4_udp(const unsigned char *px, unsigned offset_ip,
                           unsigned offset_udp, size_t udp_length) {
    uint64_t xsum = 0;

    /**
     * sum of pseudo ip header
     * NOTE: the length of pseudo ip header is even
     * */
    xsum += IP_PROTO_UDP;
    xsum += udp_length;
    xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
    xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
    xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
    xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

    /*UDP sum*/
    xsum += _checksum_calculate(&px[offset_udp], udp_length);

    /* fold and invert */
    return _checksum_finish(xsum);
}

/***************************************************************************
 ***************************************************************************/
unsigned checksum_ipv4_tcp(const unsigned char *px, unsigned offset_ip,
                           unsigned offset_tcp, size_t tcp_length) {
    uint64_t xsum = 0;

    /* pseudo checksum */
    xsum = IP_PROTO_TCP;
    xsum += tcp_length;
    xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
    xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
    xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
    xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

    /*TCP sum*/
    xsum += _checksum_calculate(&px[offset_tcp], tcp_length);

    /* fold and invert */
    return _checksum_finish(xsum);
}

#define CRC32C_POLY  0x1EDC6F41
#define CRC32C(c, d) (c = (c >> 8) ^ crc_c[(c ^ (d)) & 0xFF])

static unsigned crc_c[256] = {
    0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L, 0xC79A971FL,
    0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL, 0x8AD958CFL, 0x78B2DBCCL,
    0x6BE22838L, 0x9989AB3BL, 0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L,
    0x5E133C24L, 0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
    0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L, 0x9A879FA0L,
    0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L, 0x5D1D08BFL, 0xAF768BBCL,
    0xBC267848L, 0x4E4DFB4BL, 0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L,
    0x33ED7D2AL, 0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
    0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L, 0x6DFE410EL,
    0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL, 0x30E349B1L, 0xC288CAB2L,
    0xD1D83946L, 0x23B3BA45L, 0xF779DEAEL, 0x05125DADL, 0x1642AE59L,
    0xE4292D5AL, 0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
    0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L, 0x417B1DBCL,
    0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L, 0x86E18AA3L, 0x748A09A0L,
    0x67DAFA54L, 0x95B17957L, 0xCBA24573L, 0x39C9C670L, 0x2A993584L,
    0xD8F2B687L, 0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
    0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L, 0x96BF4DCCL,
    0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L, 0xDBFC821CL, 0x2997011FL,
    0x3AC7F2EBL, 0xC8AC71E8L, 0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L,
    0x0F36E6F7L, 0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
    0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L, 0xEB1FCBADL,
    0x197448AEL, 0x0A24BB5AL, 0xF84F3859L, 0x2C855CB2L, 0xDEEEDFB1L,
    0xCDBE2C45L, 0x3FD5AF46L, 0x7198540DL, 0x83F3D70EL, 0x90A324FAL,
    0x62C8A7F9L, 0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
    0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L, 0x3CDB9BDDL,
    0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L, 0x82F63B78L, 0x709DB87BL,
    0x63CD4B8FL, 0x91A6C88CL, 0x456CAC67L, 0xB7072F64L, 0xA457DC90L,
    0x563C5F93L, 0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
    0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL, 0x92A8FC17L,
    0x60C37F14L, 0x73938CE0L, 0x81F80FE3L, 0x55326B08L, 0xA759E80BL,
    0xB4091BFFL, 0x466298FCL, 0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL,
    0x0B21572CL, 0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
    0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L, 0x65D122B9L,
    0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL, 0x2892ED69L, 0xDAF96E6AL,
    0xC9A99D9EL, 0x3BC21E9DL, 0xEF087A76L, 0x1D63F975L, 0x0E330A81L,
    0xFC588982L, 0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
    0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L, 0x38CC2A06L,
    0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L, 0xFF56BD19L, 0x0D3D3E1AL,
    0x1E6DCDEEL, 0xEC064EEDL, 0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L,
    0xD0DDD530L, 0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
    0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL, 0x8ECEE914L,
    0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L, 0xD3D3E1ABL, 0x21B862A8L,
    0x32E8915CL, 0xC083125FL, 0x144976B4L, 0xE622F5B7L, 0xF5720643L,
    0x07198540L, 0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
    0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL, 0xE330A81AL,
    0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL, 0x24AA3F05L, 0xD6C1BC06L,
    0xC5914FF2L, 0x37FACCF1L, 0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L,
    0x7AB90321L, 0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
    0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L, 0x34F4F86AL,
    0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL, 0x79B737BAL, 0x8BDCB4B9L,
    0x988C474DL, 0x6AE7C44EL, 0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L,
    0xAD7D5351L,
};

unsigned checksum_sctp(const void *offset_sctp, size_t sctp_length) {
    const unsigned char *buffer = (const unsigned char *)offset_sctp;
    unsigned             i;
    unsigned             crc32 = (unsigned)~0;
    unsigned             result;
    unsigned char        byte0, byte1, byte2, byte3;

    for (i = 0; i < 8; i++) {
        CRC32C(crc32, buffer[i]);
    }

    CRC32C(crc32, 0);
    CRC32C(crc32, 0);
    CRC32C(crc32, 0);
    CRC32C(crc32, 0);

    for (i = 12; i < sctp_length; i++) {
        CRC32C(crc32, buffer[i]);
    }
    result = ~crc32;

    /*  result  now holds the negated polynomial remainder;
     *  since the table and algorithm is "reflected" [williams95].
     *  That is,  result has the same value as if we mapped the message
     *  to a polynomial, computed the host-bit-order polynomial
     *  remainder, performed final negation, then did an end-for-end
     *  bit-reversal.
     *  Note that a 32-bit bit-reversal is identical to four in-place
     *  8-bit reversals followed by an end-for-end byte swap.
     *  In other words, the bytes of each bit are in the right order,
     *  but the bytes have been byte swapped.  So we now do an explicit
     *  byte swap.  On a little-endian machine, this byte swap and
     *  the final ntohl cancel out and could be elided.
     */

    byte0 = result & 0xff;
    byte1 = (result >> 8) & 0xff;
    byte2 = (result >> 16) & 0xff;
    byte3 = (result >> 24) & 0xff;

    crc32 = ((unsigned)byte0 << 24) | ((unsigned)byte1 << 16) |
            ((unsigned)byte2 << 8) | byte3;
    return (crc32);
}

/*
 * Test cases for IPv4
 */
static struct {
    unsigned    checksum;
    const char *buf;
    unsigned    ip_src;
    unsigned    ip_dst;
    size_t      length;
    unsigned    ip_proto;
} ipv4packets[] = {
    {0xee9b, "\x11\x64\xee\x9b\x00\x00\x00\x00", 0x0a141e01, 0xe0000001, 8,
     IP_PROTO_IGMP},
    {0x6042,
     "\xdc\x13\x01\xbb\x00\x29\x60\x42"
     "\x5b\xd6\x16\x3a\xb1\x78\x3d\x5d\xdd\x0e\x5a\x05\x35\x74\x92\x91"
     "\x57\x4c\xaa\xc1\x85\x76\xc0\x0f\x8d\x9e\x19\xa5\xcc\xa2\x81\x65\xbe",
     0x0a141ec9, 0xadc2900a, 41, IP_PROTO_UDP},
    {0x84b2,
     "\x7e\x70\x69\x95\x1f\xb9\x77\xc6\xee\x09\x7b\x72\x50\x18\x03\xfd"
     "\x84\xb2\x00\x00"
     "\x17\x03\x03\x00\x3a\x6c\x04\xe3\x0e\x25\x79\x8e\x1c\x98\xdd\x2c"
     "\x8d\x41\x39\x53\xfb\xd0\xd5\x3e\x14\xf8\xdf\xb9\xb8\x47\xe0\x43"
     "\xab\x09\x24\x58\x7c\x6a\xab\x91\xaf\x24\xc0\x5c\xc6\xaf\x56\x45"
     "\xed\xa3\xde\x06\xa2\xd1\x79\x0a\x21\xfe\x9c\x2e\x6e\x81\x19",
     0x0a141ec9, 0xa2fec14a, 83, IP_PROTO_TCP},
    {0}};

/*
 * Test cases for IPv6
 */
static struct {
    unsigned    checksum;
    const char *buf;
    const char *ip_src;
    const char *ip_dst;
    size_t      length;
    unsigned    ip_proto;
} ipv6packets[] = {
    {0x09e3,
     "\x02\x22\x02\x23\x00\x32\x09\xe3"
     "\x0b\x15\x18\x54\x00\x06\x00\x0a\x00\x17\x00\x18\x00\x38\x00\x1f"
     "\x00\x0e\x00\x01\x00\x0e\x00\x02\x00\x00\xab\x11\xfd\xb3\xae\xbb"
     "\xe6\x57\x00\x5c\x00\x08\x00\x02\x00\x00",
     "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x07\x32\xff\xfe\x42\x5e\x35",
     "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02", 50,
     IP_PROTO_UDP},
    {0xbf3c,
     "\x8f\x00\xbf\x3c\x00\x00\x00\x04\x04\x00\x00\x00\xff\x02\x00\x00"
     "\x00\x00\x00\x00\x00\x00\x00\x01\xff\x03\x68\x4c\x04\x00\x00\x00"
     "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xd4\xa6\x80"
     "\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
     "\xff\x06\xab\x72\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00"
     "\x00\x00\x00\x01\xff\x2f\x65\x52",
     "\xfe\x80\x00\x00\x00\x00\x00\x00\x1c\x7b\x06\x42\x4e\x57\x19\xcc",
     "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16", 88,
     IP_PROTO_IPv6_ICMP},
    {0x0d0e,
     "\x8d\x59\x01\xbb\xed\xb8\x70\x8b\x91\x6c\x8d\x68\x50\x10\x04\x01"
     "\x0d\x0e\x00\x00",
     "\x20\x02\x18\x62\x5d\xeb\x00\x00\xac\xc3\x59\xad\x84\x6b\x97\x80",
     "\x26\x02\xff\x52\x00\x00\x00\x6a\x00\x00\x00\x00\x1f\xd2\x94\x5a", 20,
     IP_PROTO_TCP},
    {0}};

int checksum_selftest() {
    int      line;
    unsigned sum;
    unsigned xsum;
    unsigned i;

    /* Run through some IPv6 examples of TCP, UDP, and ICMP */
    for (i = 0; ipv6packets[i].buf; i++) {
        sum = checksum_ipv6_upper((const unsigned char *)ipv6packets[i].ip_src,
                                  (const unsigned char *)ipv6packets[i].ip_dst,
                                  ipv6packets[i].ip_proto,
                                  ipv6packets[i].length, ipv6packets[i].buf);
        if (sum != ipv6packets[i].checksum) {
            line = __LINE__;
            LOG(LEVEL_ERROR, "(%s) line=%d, index=%u \n", __func__, line, i);
            return 1; /* fail */
        }
    }

    /* Run through some IPv4 examples of TCP, UDP, and ICMP */
    for (i = 0; ipv4packets[i].buf; i++) {
        sum = checksum_ipv4_upper(ipv4packets[i].ip_src, ipv4packets[i].ip_dst,
                                  ipv4packets[i].ip_proto,
                                  ipv4packets[i].length, ipv4packets[i].buf);
        if (sum != ipv4packets[i].checksum) {
            line = __LINE__;
            LOG(LEVEL_ERROR, "(%s) line=%d, index=%u \n", __func__, line, i);
            return 1; /* fail */
        }
    }

    /*sctp*/
    const char sctp_testcase[] =
        "\xd1\x60\x00\x50\x00\x00\x00\x00\x58\xe4\x5d\x36\x01\x00\x00\x14"
        "\x9e\x8d\x52\x25\x00\x00\x80\x00\x00\x0a\x08\x00\x46\x1a\xdf\x3d";

    xsum = checksum_sctp(sctp_testcase, 32);

    if (xsum != 0x58e45d36) {
        line = __LINE__;
        LOG(LEVEL_ERROR, "(%s) line=%d, sum error\n", __func__);
        return 1;
    }

    return 0; /* success */
}
