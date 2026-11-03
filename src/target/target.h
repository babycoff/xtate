#ifndef TARGET_H
#define TARGET_H

#include "target-ipaddress.h"

/**
 * For showing ip protocol and diffing port type.
 * Ref:
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
#define IP_PROTO_HOPOPT         0 /*IPv6 Hop-by-Hop Option*/
#define IP_PROTO_ICMP           1 /*Internet Control Message*/
#define IP_PROTO_IGMP           2 /*Internet Group Management*/
#define IP_PROTO_GGP            3 /*Gateway-to-Gateway*/
#define IP_PROTO_IPv4           4 /*IPv4 encapsulation*/
#define IP_PROTO_TCP            6 /*Transmission Control*/
#define IP_PROTO_EGP            8 /*Exterior Gateway Protocol*/
/*any private interior gateway (used by Cisco for their IGRP)*/
#define IP_PROTO_IGP            9
#define IP_PROTO_UDP            17  /*User Datagram*/
#define IP_PROTO_IPv6           41  /*IPv6 encapsulation*/
#define IP_PROTO_IPv6_Route     43  /*Routing Header for IPv6*/
#define IP_PROTO_IPv6_Frag      44  /*Fragment Header for IPv6*/
#define IP_PROTO_IDRP           45  /*Inter-Domain Routing Protocol*/
#define IP_PROTO_GRE            47  /*Generic Routing Encapsulation*/
#define IP_PROTO_ESP            50  /*Encapsulating Security Payload*/
#define IP_PROTO_AH             51  /*Authentication Header*/
#define IP_PROTO_Min_IPv4       55  /*Minimal IPv4 Encapsulation (for mobile)*/
#define IP_PROTO_IPv6_ICMP      58  /*ICMP for IPv6*/
#define IP_PROTO_IPv6_NoNxt     59  /*No Next Header for IPv6*/
#define IP_PROTO_IPv6_Opts      60  /*Destination Options for IPv6*/
#define IP_PROTO_OSPFIGP        89  /*OSPF*/
#define IP_PROTO_ETHERIP        97  /*Ethernet-within-IP Encapsulation*/
#define IP_PROTO_L2TP           115 /*Layer Two Tunneling Protocol*/
#define IP_PROTO_ISIS_over_IPv4 124
#define IP_PROTO_SCTP           132 /*Stream Control Transmission Protocol*/
#define IP_PROTO_MPLS_in_IP     137
#define IP_PROTO_Other          255 /*For unregisted here or unknown type*/

const char *ip_proto_to_string(unsigned ip_proto);

/**
 * Abstract common attributes for a scanning target.
 */
typedef struct Target {
    /**
     * IP proto number to mention whether it is TCP, UDP, etc.
     * This can be used to indicate the what the port means.
     * When the ip_proto presents other protocols. The meaning of port can
     * changed by modules we use.
     * */
    unsigned  ip_proto;
    /**
     * IP of target.
     * */
    ipaddress ip_them;
    /**
     * IP of me.
     * */
    ipaddress ip_me;
    /**
     * Actual port number of target.
     * It can have many meanings for different modules.
     * */
    unsigned  port_them;
    /**
     * Actual port number of me.
     * It can have many meanings for different modules.
     * */
    unsigned  port_me;
} Target;

#endif