#ifndef STUB_PCAP_DLT_H
#define STUB_PCAP_DLT_H

/**
 * ref: https://www.tcpdump.org/linktypes.html
 * ref: https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
 */
typedef enum {
    /**
     * prefixed by an 4-bytes integer indicating the protocol type
     * in host-byte-order and followed by raw ip header.
     * Null/Loopback [VPN tunnel]
     * ref: https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
     */
    PCAP_DLT_NULL             = 0,
    PCAP_DLT_ETHERNET         = 1,   /*ethernet*/
    /**
     * pcap_datalink() returns DLT_RAW (12), not LINKTYPE_RAW (101).
     * Npcap reports 12 for TUN/VPN adapters such as Clash/Meta tunnels.
     * The savefile LINKTYPE_RAW value 101 is a different namespace.
     */
    PCAP_DLT_RAW              = 12,  /*raw ip*/
    PCAP_DLT_IEEE802_11       = 105, /*wifi, no radiotap headers*/
    /*ref: https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html*/
    PCAP_DLT_LINUX_SLL        = 113,
    /*Prism II headers (also used for things like Atheros madwifi)
     *ref: https://www.tcpdump.org/linktypes/LINKTYPE_IEEE802_11_PRISM.html*/
    PCAP_DLT_PRISM_HEADER     = 119,
    PCAP_DLT_IEEE802_11_RADIO = 127, /*wifi, with radiotap headers*/
} pcap_dlt_t;

#endif
