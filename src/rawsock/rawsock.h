/*
    raw sockets stuff
*/
#ifndef RAWSOCK_H
#define RAWSOCK_H
#include "../util-out/error-code.h"

#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/socket.h>
#endif

#include "../target/target-ipaddress.h"
#include "../stack/stack-queue.h"

/**
 * In fact the struct is like a socket in different types.
 * But we always use it like a raw socket to send from layer 2 or layer 3.
 * So it is more like an adapter.
 *
 * NOTE: Multiple tx threads will use it to send. For raw packet, it is thread
 * safe. But recving is not thread safe because of getting data repeatedly.
 */
typedef struct NetworkAdapter {
    struct pcap     *pcap;     /**/
    struct __pfring *ring;     /*optional*/
    int              raw_sock; /*for sendmmsg*/
    unsigned         is_packet_trace : 1;
    unsigned         is_vlan         : 1;
    unsigned         vlan_id;
    double           pt_start; /*start time for packet trace*/
    int              link_type;
} Adapter;

/**
 * For every Tx thread to maintain its own cache for sendqueue or sendmmsg.
 */
typedef struct Adapter_Cache {
    struct pcap_send_queue *sendq;
    unsigned                sendq_size;
#ifndef _WIN32
    struct mmsghdr *msgvec;
    struct msghdr  *msgs;
    struct iovec   *iovs;
    PktBuf         *pkt_buf;
    unsigned        msg_capacity;
    unsigned        pkt_index;
    unsigned        msg_retries;
#endif
} AdapterCache;

/**
 * Do some preparation before rawsock init.
 * e.g. try to load pcap & PFRING as stub dynamically.
 */
void rawsock_prepare(void);

/**
 * Does an "open" on the network adapter. What actually happens depends upon
 * the operating system and drivers that we are using, but usually this just
 * calls "pcap_open()"
 * @param adapter_name
 *      The name of the adapter, like "eth0" or "dna1".
 * @param is_pfring
 *      Whether we should attempt to use the PF_RING driver (Linux-only)
 * @param is_sendq
 *      Whether we should attempt to use a ring-buffer for sending packets.
 *      Currently Windows-only, but it'll be enabled for Linux soon. Big
 *      performance gains for Windows, but insignificant performance
 *      difference for Linux.
 * @param is_packet_trace
 *      Whether then Nmap --packet-trace option was set on the command-line
 * @param is_offline
 *      Whether the --offline parameter was set on the command-line. If so,
 *      then no network adapter will actually be opened.
 * @return
 *      a fully instantiated network adapter
 */
Adapter *rawsock_init_adapter(const char *adapter_name, bool is_pfring,
                              bool is_rawsock, bool is_sendmmsg, bool is_sendq,
                              bool is_packet_trace, bool is_offline,
                              bool is_vlan, unsigned vlan_id, unsigned snaplen);

void rawsock_close_adapter(Adapter *adapter);

AdapterCache *rawsock_init_cache(bool is_sendmmsg, unsigned sendmmsg_batch,
                                 unsigned sendmmsg_retries, bool is_sendq,
                                 unsigned sendq_size);

void rawsock_close_cache(AdapterCache *acache);

void rawsock_set_filter(Adapter *adapter, const char *scan_filter,
                        const char *user_filter);

/**
 * Print to the command-line the list of available adapters. It's called
 * when the "--iflist" option is specified on the command-line.
 */
void rawsock_list_adapters(void);
void rawsock_diag_target(ipaddress target, bool check, const char *forced_if);

/**
 * Queries the operating-system's network-stack in order to discover
 * the best IPv4 address to use inside our own custom network-stack.
 */
unsigned rawsock_get_adapter_ip(const char *ifname);

/**
 * Queries the operating-system's network-stack in order to discover
 * the best IPv6 address to use inside our own custom network-stack.
 */
ipv6address rawsock_get_adapter_ipv6(const char *ifname);

/**
 * Given the network adapter name, like 'eth0', find the hardware
 * MAC address. This is needed because we construct raw Ethernet
 * packets, and need to use the interface's MAC address as the
 * source address
 */
int rawsock_get_adapter_mac(const char *ifname, unsigned char *mac);

/**
 * Query the pcap link type of an interface without scanning. This opens the
 * adapter briefly, so it can fail when the process lacks capture permission.
 * Returns 0 and stores the link type on success, -1 otherwise.
 */
int rawsock_get_adapter_link_type(const char *ifname, unsigned *link_type);

/** Human-readable name for the link types Xtate understands. */
const char *rawsock_link_type_name(unsigned link_type);

int rawsock_get_default_gateway(const char *ifname, unsigned *ipv4);
int rawsock_get_default_interface(char *ifname, size_t sizeof_ifname);

const char *rawsock_win_name(const char *ifname);

int rawsock_is_adapter_names_equal(const char *lhs, const char *rhs);
int rawsock_resolve_ifname(const char *hint, char *out, size_t out_size);
int rawsock_count_default_interfaces(void);
bool rawsock_firewall_warn(const char *scanner, const char *probe);
bool rawsock_firewall_ok(void);
ErrorCode rawsock_last_error(void);

/**
 * Transmit any queued (but not yet transmitted) packets. Useful only when
 * using a high-speed transmit mechanism. Since flushing happens automatically
 * whenever the transmit queue is full, this is only needed in boundary
 * cases, like when shutting down.
 */
void rawsock_flush(Adapter *adapter, AdapterCache *acache);

/***************************************************************************
 * wrapper for libpcap's sendpacket
 *
 * PORTABILITY: WINDOWS and PF_RING
 * For performance, Windows and PF_RING can queue up multiple packets, then
 * transmit them all in a chunk. If we stop and wait for a bit, we need
 * to flush the queue to force packets to be transmitted immediately.
 * NOTE: Every `flush` operate in sendqueue or PFRING will not be executed
 * in this function except the queue or cache is full. The explicit `flush`
 * operation is in `rawsock_flush` function.
 ***************************************************************************/
int rawsock_send_packet(Adapter *adapter, AdapterCache *acache,
                        const unsigned char *packet, unsigned length);

/**
 * Called to read the next packet from the network.
 * @param adapter
 *      The network interface on which to receive packets.
 * @param length
 *      returns the length of the packet
 * @param secs
 *      returns the timestamp of the packet as a time_t value (the number
 *      of seconds since Jan 1 1970).
 * @param usecs
 *      returns part of the timestamp, the number of microseconds since the
 *      start of the current second
 * @param packet
 *      returns a pointer to the packet that was read from the network.
 *      The contents of this pointer are good until the next call to this
 *      function.
 * @return
 *      0 for success, something else for failure
 *
 */
int rawsock_recv_packet(Adapter *adapter, unsigned *length, unsigned *secs,
                        unsigned *usecs, const unsigned char **packet);

/**
 * Optimization functions to tell the underlying network stack
 * to not capture the packets we transmit. Most of the time, Ethernet
 * adapters receive the packets they send, which will cause us a lot
 * of work requiring us to process the flood of packets we generate.
 */
void rawsock_ignore_transmits(Adapter *adapter, const char *ifname);

void rawsock_set_nonblock(Adapter *adapter);

/**
 * Retrieve the datalink type of the adapter
 */
int rawsock_if_datalink(Adapter *adapter);

int rawsock_selftest_if(const char *ifname);

#endif
