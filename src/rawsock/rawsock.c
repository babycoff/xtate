/*
    portable interface to "raw sockets"

    This uses both "libpcap" on systems, but on Linux, we try to use the
    basic raw sockets, bypassing libpcap for better performance.
*/
#include "rawsock.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

#include "../xcmd.h"
#include "../version.h"
#include "../globals.h"
#include "../pixie/pixie-timer.h"

#include "../util-out/logger.h"
#include "../util-scan/ptrace.h"
#include "../util-data/fine-malloc.h"

#include "../stub/stub-pcap.h"
#include "../stub/stub-pcap-dlt.h"
#include "../stub/stub-pfring.h"
#include "../stack/stack-arpv4.h"
#include "../stack/stack-ndpv6.h"

static int      is_pcap_file = 0;
static uint64_t replay_start_wall = 0;
static uint64_t replay_start_pcap = 0;

#ifdef _WIN32
#include <winsock.h>
#include <iphlpapi.h>

#if defined(_MSC_VER)
#pragma comment(lib, "IPHLPAPI.lib")
#endif

#elif defined(__GNUC__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#else
#endif

#ifndef _WIN32
#include <netpacket/packet.h>
static struct sockaddr_ll _sockaddr;
#endif

#define PCAP_READ_TIMEOUT_MS 1000

/***************************************************************************
 ***************************************************************************/
#ifdef _WIN32
int pcap_setdirection(pcap_t *pcap, pcap_direction_t direction) {
    static int (*real_setdirection)(pcap_t *, pcap_direction_t) = 0;

    if (real_setdirection == 0) {
        void *h = LoadLibraryA("wpcap.dll");
        if (h == NULL) {
            LOG(LEVEL_ERROR, "couldn't load wpcap.dll: %u\n",
                (unsigned)GetLastError());
            return -1;
        }

        real_setdirection = (int (*)(pcap_t *, pcap_direction_t))GetProcAddress(
            h, "pcap_setdirection");
        if (real_setdirection == 0) {
            LOG(LEVEL_ERROR, "couldn't find pcap_setdirection(): %u\n",
                (unsigned)GetLastError());
            return -1;
        }
    }

    return real_setdirection(pcap, direction);
}
#endif

/***************************************************************************
 ***************************************************************************/
void rawsock_prepare(void) {
    /* load pcap as stub dynamically */
    if (pcap_init() != 0)
        LOG(LEVEL_ERROR, "(libpcap) failed to load\n");
#ifndef _WIN32
    PFRING_init();
#endif
    return;
}

/***************************************************************************
 * This function prints to the command line a list of all the network
 * interfaces/devices.
 ***************************************************************************/
void rawsock_list_adapters(void) {
    pcap_if_t *alldevs;
    char       errbuf[PCAP_ERRBUF_SIZE];

    /* load pcap as stub dynamically */
    if (pcap_init() != 0) {
        LOG(LEVEL_ERROR, "(libpcap) failed to load\n");
        return;
    }

    if (PCAP.findalldevs(&alldevs, errbuf) != -1) {
        int              i;
        const pcap_if_t *d;
        i = 0;

        if (alldevs == NULL) {
            LOG(LEVEL_ERROR,
                "libpcap: no adapters found, are you sure you are root?\n");
            return;
        }
        /* Print the list */
        for (d = alldevs; d; d = PCAP.dev_next(d)) {
            fprintf(stdout, " %d  %s \t", i++, PCAP.dev_name(d));
            if (PCAP.dev_description(d))
                fprintf(stdout, "(%s)\n", PCAP.dev_description(d));
            else
                fprintf(stdout, "(No description available)\n");
        }
        fprintf(stdout, "\n");
        PCAP.freealldevs(alldevs);
    } else {
        LOG(LEVEL_ERROR, "(%s) %s\n", __func__, errbuf);
    }
}

/***************************************************************************
 ***************************************************************************/
static const char *adapter_from_index(unsigned index) {
    pcap_if_t *alldevs;
    char       errbuf[PCAP_ERRBUF_SIZE];
    int        x;

    x = PCAP.findalldevs(&alldevs, errbuf);
    if (x != -1) {
        const pcap_if_t *d;

        if (alldevs == NULL) {
            LOG(LEVEL_ERROR,
                "libpcap: no adapters found, are you sure you are root?\n");
        }
        /* Print the list */
        for (d = alldevs; d; d = PCAP.dev_next(d)) {
            if (index-- == 0)
                return PCAP.dev_name(d);
        }
        return 0;
    } else {
        return 0;
    }
}

/***************************************************************************
 * Some methods of transmit queue multiple packets in a buffer then
 * send all queued packets at once. At the end of a scan, we might have
 * some pending packets that haven't been transmitted yet. Therefore,
 * we'll have to flush them.
 ***************************************************************************/
void rawsock_flush(Adapter *adapter, AdapterCache *acache) {
    if (adapter->ring) {
        PFRING.flush(adapter->ring);
        return;
    }

#ifndef _WIN32
    /**
     * Send in batch with sendmmsg just like ZMap v4.0
     */
    if (adapter->raw_sock && acache->msg_capacity) {
        if (acache->pkt_index == 0)
            return;

        /*set up per-retry variables, so we can only re-submit what didn't send
         * successfully*/
        struct mmsghdr *current_msg_vec         = acache->msgvec;
        int             total_packets_sent      = 0;
        int             num_of_packets_in_batch = acache->pkt_index;
        for (int i = 0; i < acache->msg_retries; i++) {
            /**
             * according to manpages:On success, sendmmsg() returns the number
             * of messages sent from msgvec; if this is less than vlen, the
             * caller can retry with a further sendmmsg() call to send the
             * remaining messages. On error, -1 is returned, and errno is set to
             * indicate the error.
             */
            int rv = sendmmsg(adapter->raw_sock, current_msg_vec,
                              num_of_packets_in_batch, 0);
            if (rv < 0) {
                /*retry if sending all packets failed*/
                LOGPERROR("sendmmsg");
                continue;
            }

            total_packets_sent += rv;
            if (rv == num_of_packets_in_batch) {
                /*all packets in batch were sent successfully*/
                break;
            }

            // batch send was only partially successful, we'll retry if we have
            // retries available
            LOG(LEVEL_ERROR,
                "(sendmmsg) only sent %d packets out of a batch of %d packets",
                total_packets_sent, acache->pkt_index);

            /**
             * per the manpages for sendmmsg, packets are sent sequentially and
             * the call returns upon a failure, returning the number of packets
             * successfully sent remove successfully sent packets from batch for
             * retry
             */
            current_msg_vec         = &acache->msgvec[total_packets_sent];
            num_of_packets_in_batch = acache->pkt_index - total_packets_sent;
        }

        acache->pkt_index = 0;
        return;
    }
#endif

    if (acache->sendq) {
        PCAP.sendqueue_transmit(adapter->pcap, acache->sendq, 0);
        /**
         * sendqueue cannot be reused because there's no way to clear it.
         */
        PCAP.sendqueue_destroy(acache->sendq);
        acache->sendq = PCAP.sendqueue_alloc(acache->sendq_size);
    }
}

int rawsock_send_packet(Adapter *adapter, AdapterCache *acache,
                        const unsigned char *packet, unsigned length) {
    /* Why: this happens in "offline mode", when we are benchmarking the
     * core algorithms without sending packets. */
    if (adapter == 0)
        return 0;

    /* A pcap savefile is a replay source, not a transmit device. */
    if (is_pcap_file)
        return 0;

    /* Print --packet-trace if debugging */
    if (adapter->is_packet_trace) {
        packet_trace(stdout, adapter->pt_start, packet, length, true);
    }

    /* PF_RING */
    if (adapter->ring) {
        int err = PF_RING_ERROR_NO_TX_SLOT_AVAILABLE;

        while (err == PF_RING_ERROR_NO_TX_SLOT_AVAILABLE) {
            err = PFRING.send(adapter->ring, packet, length, 0);
        }
        if (err < 0)
            LOG(LEVEL_WARN, "error happens in send for pfring xmit %d\n", err);
        return err;
    }

/*raw socket in link layer on Linux*/
#ifndef _WIN32
    /*use sendmmsg to send in batch*/
    if (adapter->raw_sock && acache->msg_capacity) {
        memcpy(acache->pkt_buf[acache->pkt_index].px, packet, length);
        acache->pkt_buf[acache->pkt_index].length = length;

        acache->iovs[acache->pkt_index].iov_base =
            acache->pkt_buf[acache->pkt_index].px;
        acache->iovs[acache->pkt_index].iov_len =
            acache->pkt_buf[acache->pkt_index].length;

        acache->msgs[acache->pkt_index].msg_name =
            (struct sockaddr *)&_sockaddr;
        acache->msgs[acache->pkt_index].msg_namelen =
            sizeof(struct sockaddr_ll);
        acache->msgs[acache->pkt_index].msg_iov =
            &acache->iovs[acache->pkt_index];
        acache->msgs[acache->pkt_index].msg_iovlen = 1;

        acache->msgvec[acache->pkt_index].msg_hdr =
            acache->msgs[acache->pkt_index];
        acache->msgvec[acache->pkt_index].msg_len =
            acache->pkt_buf[acache->pkt_index].length;

        acache->pkt_index++;
        if (acache->pkt_index == acache->msg_capacity) {
            rawsock_flush(adapter, acache);
        }
        return 0;
    }

    /*use sendto to send one by one*/
    if (adapter->raw_sock) {
        if (sendto(adapter->raw_sock, packet, length, 0,
                   (struct sockaddr *)&_sockaddr, sizeof(_sockaddr)) < 0) {
            perror("sendto");
            LOGPERROR("sendto");
            return -1;
        }
        return 0;
    }
#endif

    /* WINDOWS PCAP */
    /*----------------------------------------------------------------
     * PORTABILITY: WINDOWS
     *
     * The transmit rate on Windows is really slow, like 40-kpps.
     * The speed can be increased by using the "sendqueue" feature
     * to roughly 300-kpps.
     *----------------------------------------------------------------*/
    if (acache->sendq) {
        struct pcap_pkthdr hdr = {.len = length, .caplen = length};

        int err = PCAP.sendqueue_queue(acache->sendq, &hdr, packet);
        if (err) {
            rawsock_flush(adapter, acache);
            PCAP.sendqueue_queue(acache->sendq, &hdr, packet);
        }

        return 0;
    }

    /* LIBPCAP */
    if (adapter->pcap)
        return PCAP.sendpacket(adapter->pcap, packet, length);

    return 0;
}

/***************************************************************************
 ***************************************************************************/
int rawsock_recv_packet(Adapter *adapter, unsigned *length, unsigned *secs,
                        unsigned *usecs, const unsigned char **packet) {
    int err;

    if (adapter->ring) {
        /* This is for doing libpfring instead of libpcap */
        struct pfring_pkthdr hdr;

    again:
        err = PFRING.recv(adapter->ring, (unsigned char **)packet,
                          0,      /* zero-copy */
                          &hdr, 0 /* return immediately */
        );
        if (err == PF_RING_ERROR_NO_PKT_AVAILABLE || hdr.caplen == 0) {
            PFRING.poll(adapter->ring, 1);
            if (pixie_locked_fetch_u32(&time_to_finish_tx))
                return 1;
            goto again;
        }
        if (err)
            return 1;

        *length = hdr.caplen;
        *secs   = (unsigned)hdr.ts.tv_sec;
        *usecs  = (unsigned)hdr.ts.tv_usec;
    } else if (adapter->pcap) {
        struct pcap_pkthdr *hdr;

        /**
         * ret:
         *     0 if packets are being read from a live capture and the packet
         * buffer timeout expired. 1 if the packet was read without problems.
         *     PCAP_ERROR_BREAK if packets are being read from a `savefile` and
         * there are no more packets to read from the savefile.
         *     PCAP_ERROR_NOT_ACTIVATED if called on a capture handle that has
         * been created but not activated. PCAP_ERROR if an error occurred while
         * reading the packet.
         */
        err = PCAP.next_ex(adapter->pcap, &hdr, packet);

        if (err != 1) {
            if (is_pcap_file) {
                // pixie_time_set_offset(10*100000);
                pixie_locked_cas_u32(&time_to_finish_tx, 1, 0);
                pixie_locked_cas_u32(&time_to_finish_rx, 1, 0);
            }
            return 1;
        }

        *length = hdr->caplen;
        *secs   = (unsigned)hdr->ts.tv_sec;
        *usecs  = (unsigned)hdr->ts.tv_usec;

        if (is_pcap_file) {
            /* Replay at the timestamps in the savefile instead of reading the
             * whole file as fast as possible. Without this pacing a large
             * fixture can overrun the handler queues and make the test
             * non-deterministic. */
            uint64_t pcap_us = ((uint64_t)hdr->ts.tv_sec * 1000000ULL) +
                               (uint64_t)hdr->ts.tv_usec;
            uint64_t wall_us = pixie_gettime();
            if (replay_start_wall == 0) {
                replay_start_wall = wall_us;
                replay_start_pcap = pcap_us;
            } else if (pcap_us >= replay_start_pcap) {
                uint64_t target_us =
                    replay_start_wall + (pcap_us - replay_start_pcap);
                if (target_us > wall_us)
                    pixie_usleep((unsigned)(target_us - wall_us));
            }
        }
    }

    return 0;
}

/***************************************************************************
 * Used on Windows: network adapters have horrible names, so therefore we
 * use numeric indexes instead. You can which adapter you are looking for
 * by typing "--iflist" as an option.
 ***************************************************************************/
static int is_numeric_index(const char *ifname) {
    int result = 1;
    int i;

    /* empty strings aren't numbers */
    if (ifname[0] == '\0')
        return 0;

    /* 'true' if all digits */
    for (i = 0; ifname[i]; i++) {
        char c = ifname[i];

        if (c < '0' || '9' < c)
            result = 0;
    }

    return result;
}

/***************************************************************************
 * Used on Windows: if the adapter name is a numeric index, convert it to
 * the full name.
 ***************************************************************************/
const char *rawsock_win_name(const char *ifname) {
    if (is_numeric_index(ifname)) {
        const char *new_adapter_name;

        new_adapter_name = adapter_from_index(atoi(ifname));
        if (new_adapter_name)
            return new_adapter_name;
    }

    return ifname;
}

/***************************************************************************
 * Configure the socket to not capture transmitted packets. This is needed
 * because we transmit packets at a rate of millions per second, which will
 * overwhelm the receive thread.
 *
 * PORTABILITY: Windows doesn't seem to support this feature, so instead
 * what we do is apply a BPF filter to ignore the transmits, so that they
 * still get filtered at a low level.
 ***************************************************************************/
void rawsock_ignore_transmits(Adapter *adapter, const char *ifname) {
    if (adapter->ring) {
        /* PORTABILITY: don't do anything for PF_RING, because it's
         * actually done when we create the adapter, because we can't
         * reconfigure the adapter after it's been activated. */
        return;
    }

    if (adapter->pcap) {
        int err;
        err = PCAP.setdirection(adapter->pcap, PCAP_D_IN);
        if (err) {
            /*we usually cannot set direction on Windows*/
            LOG(LEVEL_INFO, "(%s) failed to set set direction for %s\n",
                __func__, ifname);
        } else {
            LOG(LEVEL_DEBUG, "(%s) setted to not receive transmits for %s\n",
                __func__, ifname);
        }
    }
}

/***************************************************************************
 ***************************************************************************/
void rawsock_close_adapter(Adapter *adapter) {
    if (adapter->ring) {
        PFRING.close(adapter->ring);
        adapter->ring = NULL;
    }
    if (adapter->pcap) {
        PCAP.close(adapter->pcap);
        adapter->pcap = NULL;
    }
#ifndef _WIN32
    if (adapter->raw_sock) {
        close(adapter->raw_sock);
        adapter->raw_sock = 0;
    }
#endif

    free(adapter);
}

/***************************************************************************
 * Does the name look like a PF_RING DNA adapter? Common names are:
 * dna0
 * dna1
 * dna0@1
 *
 ***************************************************************************/
static int is_pfring_dna(const char *name) {
    if (strlen(name) < 4)
        return 0;
    if (memcmp(name, "zc:", 3) == 0)
        return 1;
    if (memcmp(name, "dna", 3) != 0)
        return 0;

    name += 3;

    if (!isdigit(name[0] & 0xFF))
        return 0;
    while (isdigit(name[0] & 0xFF))
        name++;

    if (name[0] == '\0')
        return 1;

    if (name[0] != '@')
        return 0;
    else
        name++;

    if (!isdigit(name[0] & 0xFF))
        return 0;
    while (isdigit(name[0] & 0xFF))
        name++;

    if (name[0] == '\0')
        return 1;
    else
        return 0;
}

Adapter *rawsock_init_adapter(const char *adapter_name, bool is_pfring,
                              bool is_rawsock, bool is_sendmmsg, bool is_sendq,
                              bool is_packet_trace, bool is_offline,
                              bool is_vlan, unsigned vlan_id,
                              unsigned snaplen) {
    Adapter *adapter;
    char     errbuf[PCAP_ERRBUF_SIZE] = "pcap";

    adapter                  = CALLOC(1, sizeof(*adapter));
    adapter->is_packet_trace = is_packet_trace;
    adapter->pt_start        = 1.0 * pixie_gettime() / 1000000.0;

    adapter->is_vlan = is_vlan;
    adapter->vlan_id = vlan_id;

    if (is_offline) {
        return adapter;
    }

    /*----------------------------------------------------------------
     * PORTABILITY: WINDOWS
     * If is all digits index, then look in indexed list
     *----------------------------------------------------------------*/
    if (is_numeric_index(adapter_name)) {
        const char *new_adapter_name;

        new_adapter_name = adapter_from_index(atoi(adapter_name));
        if (new_adapter_name == 0) {
            LOG(LEVEL_ERROR, "pcap_open_live(%s) error: bad index\n",
                adapter_name);
            return 0;
        } else
            adapter_name = new_adapter_name;
    }

    /*----------------------------------------------------------------
     * PORTABILITY: PF_RING
     *  If we've been told to use --pfring, then attempt to open the
     *  network adapter using the PF_RING API rather than libpcap.
     *  Since a lot of things can go wrong, we do a lot of extra
     *  logging here.
     *----------------------------------------------------------------*/
    if (is_pfring &&
        !is_pfring_dna(
            adapter_name)) { /*First ensure pfring dna adapter is available*/
        LOG(LEVEL_ERROR,
            "no pfring adapter available. Please install pfring or "
            "run " XTATE_NAME " without the --pfring option.\n");
        return 0;
    }

    if (is_pfring_dna(adapter_name)) {
        int      err;
        unsigned version;

        /*
         * Open
         *
         * TODO: Do we need the PF_RING_REENTRANT flag? We only have one
         * transmit and one receive thread, so I don't think we need it.
         * Also, this reduces performance in half, from 12-mpps to
         * 6-mpps.
         * NOTE: I don't think it needs the "re-entrant" flag, because it
         * transmit and receive are separate functions?
         */
        LOG(LEVEL_DETAIL, "(pfring:'%s') opening...\n", adapter_name);

        adapter->ring      = PFRING.open(adapter_name, snaplen,
                                         0); // 1500, PF_RING_REENTRANT);
        adapter->pcap      = (pcap_t *)adapter->ring;
        adapter->link_type = PCAP_DLT_ETHERNET;

        if (adapter->ring == NULL) {
            LOG(LEVEL_ERROR, "(pfring:'%s') OPEN ERROR: %s\n", adapter_name,
                strerror(errno));
            return 0;
        } else
            LOG(LEVEL_DETAIL, "(pfring:'%s') successfully opened\n",
                adapter_name);

        /*
         * Housekeeping
         */
        PFRING.set_application_name(adapter->ring, XTATE_NAME);
        PFRING.version(adapter->ring, &version);
        LOG(LEVEL_DEBUG, "(pfring) version %d.%d.%d\n",
            (version >> 16) & 0xFFFF, (version >> 8) & 0xFF,
            (version >> 0) & 0xFF);

        LOG(LEVEL_DETAIL, "(pfring:'%s') setting direction\n", adapter_name);
        err = PFRING.set_direction(adapter->ring, rx_only_direction);
        if (err) {
            LOG(LEVEL_ERROR, "(pfring:'%s') setdirection = %d\n", adapter_name,
                err);
        } else
            LOG(LEVEL_DETAIL, "(pfring:'%s') direction success\n",
                adapter_name);

        /*
         * Activate
         *
         * PF_RING requires a separate activation step.
         */
        LOG(LEVEL_DETAIL, "(pfring:'%s') activating\n", adapter_name);
        err = PFRING.enable_ring(adapter->ring);
        if (err != 0) {
            LOG(LEVEL_ERROR, "(pfring:'%s') ENABLE ERROR: %s\n", adapter_name,
                strerror(errno));
            PFRING.close(adapter->ring);
            adapter->ring = 0;
            return 0;
        } else
            LOG(LEVEL_INFO, "(pfring:'%s') successfully enabled\n",
                adapter_name);

        return adapter;
    }

    /*----------------------------------------------------------------
     * Kludge: for using files
     *----------------------------------------------------------------*/
    if (memcmp(adapter_name, "file:", 5) == 0) {
        LOG(LEVEL_DETAIL, "(pcap) file: %s\n", adapter_name + 5);
        is_pcap_file  = 1;
        adapter->pcap = PCAP.open_offline(adapter_name + 5, errbuf);
        if (adapter->pcap == NULL) {
            LOG(LEVEL_ERROR, "(pcap) file: %s: %s\n", adapter_name + 5,
                errbuf);
            FREE(adapter);
            return 0;
        }
        adapter->link_type = PCAP.datalink(adapter->pcap);
        /* A savefile is a receive-only source. Do not fall through to the
         * live/libpcap path, which would try to activate "file:..." as a
         * device. */
        return adapter;
    }
    /*----------------------------------------------------------------
     * PORTABILITY: LIBPCAP
     *
     * This is the standard that should work everywhere.
     *----------------------------------------------------------------*/
    {
        int err;
        LOG(LEVEL_INFO, "if(%s): pcap: %s\n", adapter_name, PCAP.lib_version());
        LOG(LEVEL_DETAIL, "if(%s): opening...\n", adapter_name);

        /* This reserves resources, but doesn't actually open the
         * adapter until we call pcap_activate */
        adapter->pcap = PCAP.create(adapter_name, errbuf);
        if (adapter->pcap == NULL) {
            LOG(LEVEL_HINT, "(PCAP) use `open_live` instead of `activate`, "
                            "this may cause send rate a little slow.\n");
            /**
             * NOTE: If going to this way, send rate of pcap will be a little
             * bit slower. I cannot explain this.
             * */
            adapter->pcap = PCAP.open_live(
                adapter_name, snaplen, 8, /* promiscuous mode */
                PCAP_READ_TIMEOUT_MS,     /* read timeout in milliseconds */
                errbuf);
            if (adapter->pcap == NULL) {
                LOG(LEVEL_ERROR, "(if:%s) can't open adapter: %s\n",
                    adapter_name, errbuf);
                if (strstr(errbuf, "perm")) {
                    LOG(LEVEL_ERROR, "permission denied\n");
                    LOG(LEVEL_HINT,
                        "need to sudo or run as root or administrator\n");
                }
                return 0;
            }
        } else {
            err = PCAP.set_snaplen(adapter->pcap, snaplen);
            if (err) {
                LOGPCAPERROR(adapter->pcap, "pcap_set_snaplen");
                goto pcap_error;
            }

            err = PCAP.set_promisc(adapter->pcap, 8);
            if (err) {
                LOGPCAPERROR(adapter->pcap, "pcap_set_promisc");
                goto pcap_error;
            }

            /**
             * Pcap has packet buffer to store recved packets. It will return
             * packets to caller just when the buffer is full or reaches
             * `timeout` in pcap's default config. Not setting or set timeout to
             * 0, negative will cause undefined action. It is recommended to set
             * timeout to a non-zero value.
             * NOTE: Manual says timeout will be disgarded if pcap is in
             * immediate mode. But I saw it has effect while setting both block
             * mode and immediate mode.
             */
            err = PCAP.set_timeout(adapter->pcap, PCAP_READ_TIMEOUT_MS);
            if (err) {
                LOGPCAPERROR(adapter->pcap, "pcap_set_timeout");
                goto pcap_error;
            }

            /**
             * Immediate mode means that pcap will use no buffer for recving and
             * return it to caller just when recved.
             * NOTE: Manual says this will cause timeout setting be disgarded.
             * But I saw it has effect while setting both block mode and
             * immediate mode.
             */
            err = PCAP.set_immediate_mode(adapter->pcap, 1);
            if (err) {
                LOGPCAPERROR(adapter->pcap, "pcap_set_immediate_mode");
                goto pcap_error;
            }

            /* If errors happen, they aren't likely to happen above, but will
             * happen where when they are applied */
            err = PCAP.activate(adapter->pcap);
            switch (err) {
                case 0:
                    /* drop down below */
                    break;
                case PCAP_ERROR_PERM_DENIED:
                    LOG(LEVEL_ERROR,
                        "(%s) permission denied while activating PCAP\n",
                        __func__);
                    LOG(LEVEL_HINT,
                        "need to sudo or run as root or administrator\n");
                    goto pcap_error;
                default:
                    LOGPCAPERROR(adapter->pcap, "pcap_activate");
                    if (err < 0)
                        goto pcap_error;
            }
        }

        LOG(LEVEL_INFO, "if(%s): successfully opened\n", adapter_name);

        /* Figure out the link-type. We suport Ethernet and IP */
        adapter->link_type = PCAP.datalink(adapter->pcap);
        switch (adapter->link_type) {
            case -1:
                LOGPCAPERROR(adapter->pcap, "pcap_datalink");
                goto pcap_error;
            case PCAP_DLT_NULL:
                LOG(LEVEL_DEBUG, "if(%s): VPN tunnel interface found\n",
                    adapter_name);
                break;
            case PCAP_DLT_ETHERNET:
            case PCAP_DLT_RAW:
                break;
            default:
                LOG(LEVEL_ERROR, "if(%s): unknown data link type: %u(%s)\n",
                    adapter_name, adapter->link_type,
                    PCAP.datalink_val_to_name(adapter->link_type));
                break;
        }
    }

/**
 * init raw socket for sendto or sendmmsg
 */
#ifndef _WIN32
#include <netinet/if_ether.h>
    if (is_rawsock || is_sendmmsg) {
        /**
         * NOTE: ZMap use PF_INET family on raw socket to send IPv4 in IP layer.
         * But Xtate need to send both IPv4 and IPv6 packets in one socket in
         * sendmmsg way. We can't achieve this in an elegent way by raw socket.
         * So we just accept sending packet in Link Layer.
         */
        if (adapter->link_type != PCAP_DLT_ETHERNET) {
            LOG(LEVEL_WARN, "(%s) sendmmsg just work on link layer\n",
                __func__);
            return adapter;
        }

        adapter->raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (adapter->raw_sock <= 0) {
            LOGPERROR("socket init");
            goto pcap_error;
        }

        /*bind to specified interface*/
        struct ifreq if_idx;
        memset(&if_idx, 0, sizeof(struct ifreq));
        if (strlen(adapter_name) >= IFNAMSIZ) {
            LOG(LEVEL_ERROR, "(%s) device interface name (%s) too long\n",
                __func__, adapter_name);
            goto socket_error;
        }
        strncpy(if_idx.ifr_name, adapter_name, IFNAMSIZ - 1);
        if (ioctl(adapter->raw_sock, SIOCGIFINDEX, &if_idx) < 0) {
            LOGPERROR("ioctl(SIOCGIFINDEX)");
            goto socket_error;
        }

        /*set destination*/
        memset((void *)&_sockaddr, 0, sizeof(struct sockaddr_ll));
        _sockaddr.sll_ifindex = if_idx.ifr_ifindex;
        _sockaddr.sll_family  = AF_PACKET;

        return adapter;

    socket_error:
        if (adapter->raw_sock) {
            close(adapter->raw_sock);
            adapter->raw_sock = 0;
        }
    }

#endif

    return adapter;

pcap_error:
    if (adapter->pcap) {
        PCAP.close(adapter->pcap);
        adapter->pcap = NULL;
    }
    if (adapter->pcap == NULL) {
        if (strcmp(adapter_name, "vmnet1") == 0) {
            LOG(LEVEL_ERROR,
                "VMware on Macintosh doesn't support " XTATE_NAME "\n");
        }
        return 0;
    }

    return NULL;
}

void rawsock_set_filter(Adapter *adapter, const char *scan_filter,
                        const char *user_filter) {
    if (!adapter->pcap)
        return;

    const char *final_filter;
    if (user_filter && user_filter[0]) {
        final_filter = user_filter;
    } else if (scan_filter && scan_filter[0]) {
        final_filter = scan_filter;
    } else {
        return;
    }

    LOG(LEVEL_DEBUG, "final BPF filter: %s\n", final_filter);

    /**
     * set BPF filter
     */
    int                err;
    struct bpf_program bpfp;

    err = PCAP.compile(adapter->pcap, &bpfp, final_filter, 1, 0);
    if (err) {
        LOGPCAPERROR(adapter->pcap, "pcap_compile");
        xcmd_try_reboot();
        exit(1);
    }

    err = PCAP.setfilter(adapter->pcap, &bpfp);
    if (err) {
        LOGPCAPERROR(adapter->pcap, "pcap_setfilter");
        xcmd_try_reboot();
        exit(1);
    }

    PCAP.freecode(&bpfp);
}

/**
 * Nonblock mode means pcap will return immediatelly even if no packet recved.
 */
void rawsock_set_nonblock(Adapter *adapter) {
    /* Savefiles are always read synchronously; pcap_setnonblock rejects them. */
    if (is_pcap_file)
        return;

    if (adapter->pcap) {
        int  err;
        char errbuf[PCAP_ERRBUF_SIZE] = "pcap";

        err = PCAP.setnonblock(adapter->pcap, 1, errbuf);
        if (err) {
            LOGPCAPERROR(adapter->pcap, "pcap_setnonblock");
            xcmd_try_reboot();
            exit(1);
        }
    }
}

/***************************************************************************
 * for testing when two Windows adapters have the same name. Sometimes
 * the \Device\NPF_ string is prepended, sometimes not.
 ***************************************************************************/
int rawsock_is_adapter_names_equal(const char *lhs, const char *rhs) {
    if (memcmp(lhs, "\\Device\\NPF_", 12) == 0)
        lhs += 12;
    if (memcmp(rhs, "\\Device\\NPF_", 12) == 0)
        rhs += 12;
    return strcmp(lhs, rhs) == 0;
}

/***************************************************************************
 ***************************************************************************/
AdapterCache *rawsock_init_cache(bool is_sendmmsg, unsigned sendmmsg_batch,
                                 unsigned sendmmsg_retries, bool is_sendq,
                                 unsigned sendq_size) {
    AdapterCache *acache = CALLOC(1, sizeof(AdapterCache));
#ifdef _WIN32
    if (is_sendq) {
        if (sendq_size == 0) {
            LOG(LEVEL_ERROR, "(%s) sendqueue size cannot be zero\n", __func__);
            xcmd_try_reboot();
            exit(1);
        }
        acache->sendq_size = sendq_size;
        acache->sendq      = PCAP.sendqueue_alloc(acache->sendq_size);
    }
#else
    if (is_sendmmsg) {
        if (sendmmsg_batch == 0) {
            LOG(LEVEL_ERROR, "(%s) sendmmsg batch cannot be zero\n", __func__);
            xcmd_try_reboot();
            exit(1);
        }
        if (sendmmsg_retries == 0) {
            LOG(LEVEL_ERROR, "(%s) sendmmsg retries cannot be zero\n",
                __func__);
            xcmd_try_reboot();
            exit(1);
        }
        acache->msg_capacity = sendmmsg_batch;
        acache->msg_retries  = sendmmsg_retries;
        acache->msgvec  = CALLOC(acache->msg_capacity, sizeof(struct mmsghdr));
        acache->msgs    = CALLOC(acache->msg_capacity, sizeof(struct msghdr));
        acache->iovs    = CALLOC(acache->msg_capacity, sizeof(struct iovec));
        acache->pkt_buf = CALLOC(acache->msg_capacity, sizeof(PktBuf));
    }
#endif

    return acache;
}

void rawsock_close_cache(AdapterCache *acache) {
#ifdef _WIN32
    if (acache->sendq) {
        PCAP.sendqueue_destroy(acache->sendq);
    }
#else
    if (acache->msg_capacity) {
        FREE(acache->msgvec);
        FREE(acache->msgs);
        FREE(acache->iovs);
        FREE(acache->pkt_buf);
    }
#endif

    FREE(acache);
}

/***************************************************************************
 ***************************************************************************/
int rawsock_if_datalink(Adapter *adapter) {
    if (adapter->ring)
        return PCAP_DLT_ETHERNET;
    else {
        return adapter->link_type;
    }
}

int rawsock_selftest_if(const char *ifname) {
    int                   err;
    ipv4address_t         ipv4 = 0;
    ipv6address_t         ipv6;
    ipv4address_t         router_ipv4 = 0;
    macaddress_t          source_mac  = {{0, 0, 0, 0, 0, 0}};
    Adapter              *adapter;
    AdapterCache         *acache;
    char                  ifname2[246];
    ipaddress_formatted_t fmt;

    /* load pcap as stub dynamically */
    if (pcap_init() != 0)
        LOG(LEVEL_ERROR, "(libpcap) failed to load\n");

    // rawsock_prepare();

    /*
     * Get the interface
     */
    if (ifname == NULL || ifname[0] == 0) {
        err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err) {
            printf("if = not found (err=%d)\n", err);
            return -1;
        }
        ifname = ifname2;
    }
    printf("if = %s\n", ifname);

    /*
     * Initialize the adapter.
     */
    adapter = rawsock_init_adapter(ifname, false, false, false, false, false,
                                   false, false, 0, 65535);
    if (adapter == 0) {
        puts("pcap = failed");
        return -1;
    } else {
        puts("pcap = opened");
    }

    acache = rawsock_init_cache(false, 0, 0, false, 0);

    /* IPv4 address */
    ipv4 = rawsock_get_adapter_ip(ifname);
    if (ipv4 == 0) {
        puts("source-ipv4 = not found (err)");
    } else {
        fmt = ipv4address_fmt(ipv4);
        printf("source-ipv4 = %s\n", fmt.string);
    }

    /* IPv6 address */
    ipv6 = rawsock_get_adapter_ipv6(ifname);
    if (ipv6address_is_zero(ipv6)) {
        puts("source-ipv6 = not found");
    } else {
        fmt = ipv6address_fmt(ipv6);
        printf("source-ipv6 = [%s]\n", fmt.string);
    }

    /* MAC address */
    err = rawsock_get_adapter_mac(ifname, source_mac.addr);
    if (err) {
        printf("source-mac = not found (err=%d)\n", err);
    } else {
        fmt = macaddress_fmt(source_mac);
        printf("source-mac = %s\n", fmt.string);
    }

    switch (adapter->link_type) {
        case 0:
            puts("router-ip = implicit");
            puts("router-mac = implicit");
            break;
        default:
            /* IPv4 router IP address */
            err = rawsock_get_default_gateway(ifname, &router_ipv4);
            if (err) {
                printf("router-ip = not found(err=%d)\n", err);
            } else {
                fmt = ipv4address_fmt(router_ipv4);
                printf("router-ip = %s\n", fmt.string);
            }

            /* IPv4 router MAC address */
            {
                macaddress_t router_mac = {{0, 0, 0, 0, 0, 0}};

                stack_arp_resolve(adapter, acache, ipv4, source_mac,
                                  router_ipv4, &router_mac);

                if (macaddress_is_zero(router_mac)) {
                    puts("router-mac-ipv4 = not found");
                } else {
                    fmt = macaddress_fmt(router_mac);
                    printf("router-mac-ipv4 = %s\n", fmt.string);
                }
            }

            /*
             * IPv6 router MAC address.
             * If it's not configured, then we need to send a (synchronous)
             * query to the network in order to discover the location of routers
             * on the local network
             */
            if (!ipv6address_is_zero(ipv6)) {
                macaddress_t router_mac = {{0, 0, 0, 0, 0, 0}};

                stack_ndpv6_resolve(adapter, acache, ipv6, source_mac,
                                    &router_mac);

                if (macaddress_is_zero(router_mac)) {
                    puts("router-mac-ipv6 = not found");
                } else {
                    fmt = macaddress_fmt(router_mac);
                    printf("router-mac-ipv6 = %s\n", fmt.string);
                }
            }
    }

    rawsock_close_cache(acache);
    rawsock_close_adapter(adapter);
    return 0;
}
