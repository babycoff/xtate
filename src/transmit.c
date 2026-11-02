#include "transmit.h"
#include "generate-modules/generate-modules.h"
#include "scan-modules/scan-modules.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "globals.h"
#include "xconf.h"
#include "version.h"
#include "rawsock/rawsock.h"

#include "pixie/pixie-threads.h"
#include "pixie/pixie-timer.h"

#include "util-out/logger.h"
#include "util-scan/throttle.h"

static void _adapter_get_source_addresses(const XConf     *xconf,
                                          struct source_t *src) {
    const StackSrc *ifsrc = &xconf->nic.src;

    src->ipv4      = ifsrc->ipv4.first;
    src->ipv4_mask = ifsrc->ipv4.last - ifsrc->ipv4.first;

    src->ipv6      = ifsrc->ipv6.first;
    src->ipv6_mask = ifsrc->ipv6.last.lo - ifsrc->ipv6.first.lo;

    src->port      = ifsrc->port.first;
    src->port_mask = ifsrc->port.last - ifsrc->port.first;
}

void transmit_thread(void *v) {
    TxThread     *parms        = (TxThread *)v;
    const XConf  *xconf        = parms->xconf;
    Throttler    *throttler    = parms->throttler;
    Adapter      *adapter      = xconf->nic.adapter;
    AdapterCache *acache       = NULL;
    uint64_t      packets_sent = 0;
    unsigned      increment    = xconf->shard.of * xconf->tx_thread_count;
    uint64_t      entropy      = xconf->seed;
    Generator    *generator    = xconf->generator;

    /* Wait to make sure receive_thread is ready */
    pixie_usleep(1000000);
    LOG(LEVEL_DEBUG, "starting transmit thread #%u\n", parms->tx_index);

    char th_name[30];
    snprintf(th_name, sizeof(th_name), XTATE_NAME "-xmit #%u", parms->tx_index);
    pixie_set_thread_name(th_name);

    /* Lock threads to the CPUs one by one in this order:
     *     1.Tx threads
     *     2.Rx thread
     *     3.Rx handle threads
     * TODO: Make CPU locking be settable.
     */
    if (pixie_cpu_get_count() > 1 && !xconf->is_no_cpu_bind) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu_index = parms->tx_index;
        /* I think it is better to make (cpu>=cpu_count) threads free */
        if (cpu_index < cpu_count)
            pixie_cpu_set_affinity(cpu_index);
    }

    /* Normally, we have just one source address. In special cases, though
     * we can have multiple. */
    struct source_t src;
    _adapter_get_source_addresses(xconf, &src);

    /**
     * init tx's own adapter transmit cache.
     */
    acache = rawsock_init_cache(xconf->is_sendmmsg, xconf->sendmmsg_batch,
                                xconf->sendmmsg_retries, xconf->is_sendq,
                                xconf->sendq_size);

    throttler_start(throttler, xconf->max_rate / xconf->tx_thread_count);

    /*Declared out of infinite loop to keep balance of stack*/
    uint64_t start;
    uint64_t batch_size;
    unsigned more_idx;

infinite:;

    start = xconf->resume.index + parms->tx_index +
            (xconf->shard.one - 1) * xconf->tx_thread_count;

    /**
     * NOTE: This init insures the stop of tx while the tx thread got no target
     * to scan.
     */
    pixie_locked_store_u64(&parms->my_index, start);

    LOG(LEVEL_DEBUG, "(tx thread) starting main loop from: %llu inc: %llu\n",
        start, increment);

    more_idx = 0;
    for (uint64_t i = start; generator->hasmore_cb(parms->tx_index, i);) {
        batch_size = throttler_next_batch(throttler, packets_sent);

        /*Transmit packets from stack first */
        stack_flush_packets(xconf->stack, adapter, acache, &packets_sent,
                            &batch_size);

        while (batch_size && generator->hasmore_cb(parms->tx_index, i)) {
            ScanTarget target = {.index = more_idx};

            target.target = generator->generate_cb(
                parms->tx_index, i, pixie_locked_fetch_u64(&parms->my_repeat),
                &src);

            unsigned char pkt_buf[PKT_BUF_SIZE];
            size_t        pkt_len = 0;
            unsigned      more    = 0;
            more = xconf->scanner->transmit_cb(entropy, &target, pkt_buf,
                                               &pkt_len);

            /*
             * Send packet actually.
             * No explicit sock flushing in this loop because I assume there are
             * always enough packets here to trigger implicit flushing.
             */
            if (pkt_len) {
                rawsock_send_packet(adapter, acache, pkt_buf,
                                    (unsigned)pkt_len);

                batch_size--;
                packets_sent++;
                pixie_locked_add_u64(&parms->total_sent, 1);
            }

            if (more) {
                more_idx++;
            } else {
                i += increment;
                more_idx = 0;
            }

            /**
             * avoid infinite loop after ctrl+C if always no packet was sent
             * */
            if (!pkt_len)
                break;

        } /* end of batch */

        /* save our current location for resuming */
        pixie_locked_store_u64(&parms->my_index, i);

        /* If the user pressed <ctrl-c>, then we need to exit and save state.*/
        if (pixie_locked_fetch_u32(&time_to_finish_tx)) {
            break;
        }
    }

    /*
     * --infinite, --repeat, --static-seed
     * Set repeat as condition to avoid more packets sending.
     */
    if (xconf->is_infinite && !pixie_locked_fetch_u32(&time_to_finish_tx)) {
        if ((xconf->repeat &&
             pixie_locked_fetch_u64(&parms->my_repeat) < xconf->repeat) ||
            !pixie_locked_fetch_u64(&parms->my_repeat)) {
            pixie_locked_add_u64(&parms->my_repeat, 1);
            goto infinite;
        }
    }

    /*
     * Makes sure all packets are transmitted while in sendq or PF_RING mode.
     */
    rawsock_flush(adapter, acache);

    LOG(LEVEL_DEBUG, "transmit thread #%u complete\n", parms->tx_index);

    /*
     * Help rx thread to do further response.
     * Packets for sending here are not always enough to trigger implicit sock
     * flush. So do explicit flush for less latency.
     */
    while (!pixie_locked_fetch_u32(&time_to_finish_rx)) {
        batch_size = throttler_next_batch(throttler, packets_sent);
        stack_flush_packets(xconf->stack, adapter, acache, &packets_sent,
                            &batch_size);
        rawsock_flush(adapter, acache);
    }

    /*clean adapter transmit cache*/
    rawsock_close_cache(acache);
    acache = NULL;

    parms->done_transmitting = true;
    LOG(LEVEL_DEBUG, "exiting transmit thread #%u                    \n",
        parms->tx_index);
}
