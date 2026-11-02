/* Copyright: (c) 2009-2010 by Robert David Graham */
/* Modified: Alvin Chen 2024*/
#ifndef PREPROCESS_H
#define PREPROCESS_H

#include "../target/target-ipaddress.h"

/**
 * ref: https://en.wikipedia.org/wiki/EtherType
 */
#define ETHERTYPE_IPv4       0x0800
#define ETHERTYPE_ARP        0x0806
#define ETHERTYPE_WAKEonLAN  0x0842
#define ETHERTYPE_CISCO_DIS  0x2000
#define ETHERTYPE_VLAN_8021Q 0x8100
#define ETHERTYPE_IPX        0x8137
#define ETHERTYPE_IPv6       0x86dd
#define ETHERTYPE_MLPS_UNI   0x8847
#define ETHERTYPE_MLPS_MUL   0x8848

typedef enum PreprocessedFoundProtocol {
    FOUND_NOTHING = 0,
    FOUND_ETHERNET,
    FOUND_IPV4,
    FOUND_IPV6,
    FOUND_ICMP,
    FOUND_TCP,
    FOUND_UDP,
    FOUND_SCTP,
    FOUND_IPV6_HOP,
    FOUND_8021Q,
    FOUND_MPLS,
    FOUND_WIFI_DATA,
    FOUND_WIFI,
    FOUND_RADIOTAP,
    FOUND_PRISM,
    FOUND_LLC,
    FOUND_ARP,
    FOUND_SLL,    /* Linux SLL */
    FOUND_OPROTO, /* some other IP protocol */
    FOUND_IGMP,
    FOUND_NDPv6,
} FoundProto;

typedef struct PreprocessedInfo {
    /**
     * Link layer
     */
    const unsigned char *mac_src;
    const unsigned char *mac_dst;
    const unsigned char *mac_bss; /*for 802.11*/
    struct {
        uint16_t hardware_type;
        uint16_t protocol_type;
        uint8_t  hardware_size;
        uint8_t  protocol_size;
        uint16_t opcode;

        const unsigned char *sender_mac;
        const unsigned char *target_mac;
    } arp_info;
    /**
     * IP/Network layer
     */
    unsigned             ip_offset; /* 14 for normal Ethernet */
    uint8_t              ip_version;
    uint8_t              ip_protocol;
    uint16_t             ip_v4_length; /* length packet from ipv4 layer*/
    uint8_t              ip_ttl;       /* ttl for ipv4 or hop limit for ipv6*/
    uint16_t             ip_v4_id;
    /*point to actual ip data*/
    const unsigned char *_ip_src;
    const unsigned char *_ip_dst;
    /*ip info after parsed*/
    ipaddress            src_ip;
    ipaddress            dst_ip;
    /**
     * Transport layer
     */
    unsigned             transport_offset; /* 34 for normal Ethernet */
    unsigned             transport_length;
    uint8_t              icmp_type;
    uint8_t              icmp_code;
    uint16_t             icmp_id;
    uint16_t             icmp_seqno;
    uint16_t             port_src;
    uint16_t             port_dst;
    /**
     * Application layer
     * NOTE: also for icmp echo
     */
    unsigned             app_offset;
    unsigned             app_length;
    /**
     * The latest found proto
     */
    FoundProto           found;
    int                  found_offset;
} PreInfo;

/**
 * This function can be not only used to parse raw packets, but also be used to
 * parse some wrapped content like payload of ICMP messages by passing content
 * buffer with link type PCAP_DLT_RAW(101).
 * NOTE: Payload content should be valid packet if parsing recursively. Or we
 * must conditionally ignore the retured value of preprocess.
 * @return true if useful stuff found, false otherwise
 */
bool preprocess_frame(const unsigned char *px, unsigned length,
                      unsigned link_type, PreInfo *info);

int preprocess_selftest(void);

#endif
