#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xconf.h"
#include "xcmd.h"
#include "globals.h"
#include "receive.h"
#include "version.h"
#include "transmit.h"

#include "rawsock/rawsock.h"
#include "templ/templ-init.h"
#include "nmap/nmap-service.h"
#include "stack/stack-queue.h"
#include "target/target-cookie.h"

#include "pixie/pixie-file.h"
#include "pixie/pixie-timer.h"
#include "pixie/pixie-threads.h"
#include "pixie/pixie-backtrace.h"

#include "util-out/logger.h"
#include "util-misc/i18n.h"
#include "util-out/xtatus.h"
#include "util-scan/init-nic.h"
#include "util-data/fine-malloc.h"
#include "util-data/safe-string.h"
#include "util-scan/list-targets.h"

#include "output-modules/bson-output.h"
#include "output-modules/mongodb-output.h"

#if defined(_WIN32)
#include <WinSock.h>
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define _LOOP_SLEEP_MS 350

/*
 * These are global variables, see globals.h
 */
unsigned volatile time_to_finish_tx = 0;
unsigned volatile time_to_finish_rx = 0;
time_t   global_now;
TmplSet *global_tmplset;

static uint64_t _usec_start;

static void _control_c_handler(int x) {
    static unsigned control_c_pressed = 0;

    if (control_c_pressed == 0) {
        LOG(LEVEL_OUT, "waiting several seconds to exit..."
                       "                                                       "
                       "                    \n");
        /*First time of <ctrl-c>, tell Tx to stop*/
        control_c_pressed = 1;
        pixie_locked_cas_u32(&time_to_finish_tx, 1, 0);
    } else {
        if (pixie_locked_fetch_u32(&time_to_finish_rx)) {
            /*Not first time of <ctrl-c> */
            /*and Rx is exiting, we just warn*/
            LOG(LEVEL_OUT, "\nERROR: Rx Thread is still running\n");
            /*Exit many <ctrl-c>*/
            if (pixie_locked_fetch_u32(&time_to_finish_rx) > 1) {
                xcmd_try_reboot();
                exit(1);
            }
            pixie_locked_add_u32(&time_to_finish_rx, 1);
        } else {
            /*Not first time of <ctrl-c> */
            /*and we are waiting now*/
            /*tell Rx to exit*/
            pixie_locked_add_u32(&time_to_finish_rx, 1);
        }
    }
}

static int _main_scan(XConf *xconf) {
    /**
     * According to C99 standards while using designated initializer:
     *
     *     "Omitted fields are implicitly initialized the same as for objects
     * that have static storage duration."
     *
     * ref: https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html
     *
     * This is more efficient to got an all-zero var than memset and could got
     * a partial-zero var conveniently.
     */
    FILE      *meta_fp         = NULL;
    bool       stop_tx         = true;
    uint64_t   count_targets   = 0;
    uint64_t   count_endpoints = 0;
    uint64_t   scan_range      = 0;
    bool       init_ipv4       = false;
    bool       init_ipv6       = false;
    time_t     now             = time(0);
    TmplSet    tmplset         = {0};
    Xtatus     status          = {.last = {0}};
    XtatusItem status_item     = {0};
    RxThread   rx_thread[1]    = {{0}};
    TxThread  *tx_thread;
    double     tx_free_entries;
    double     rx_free_entries;
    double     rx_queue_ratio_tmp;

    tx_thread = CALLOC(xconf->tx_thread_count, sizeof(TxThread));

    /*
     * Set modules at first for dependency checking in module initing.
     * Output & Probe don't need explicit default setting.
     */
    if (!xconf->generator) {
        xconf->generator = get_generate_module_by_name("blackrock");
        LOG(LEVEL_INFO, "default GenerateModule `blackrock` is chosen because "
                        "no GenerateModule was specified.\n");
    }
    if (!xconf->scanner) {
        LOG(LEVEL_ERROR, "no scan module was specified.\n");
        LOG(LEVEL_HINT, "use `-scan` to specify a scan module.\n");
        xcmd_try_reboot();
        exit(1);
    }

    /*validate probe type*/
    if (xconf->scanner->required_probe_type == ProbeType_NULL) {
        if (xconf->probe) {
            LOG(LEVEL_ERROR, "ScanModule %s does not support any probe.\n",
                xconf->scanner->name);
            xcmd_try_reboot();
            exit(1);
        }
    } else {
        if (!xconf->probe ||
            xconf->probe->type != xconf->scanner->required_probe_type) {
            LOG(LEVEL_ERROR, "ScanModule %s needs probe of %s type.\n",
                xconf->scanner->name,
                get_probe_type_name(xconf->scanner->required_probe_type));
            xcmd_try_reboot();
            exit(1);
        }
    }

    /*
     * Config params & Do global init for GenerateModule
     */
    if (xconf->probe && strncmp(xconf->probe->name, "lua-", 4) == 0 &&
        xconf->rx_handler_count != 1) {
        LOG(LEVEL_WARN,
            "Lua probe `%s` uses a single global Lua state; forcing "
            "--rx-handler-count 1 (was %u)\n",
            xconf->probe->name, xconf->rx_handler_count);
        xconf->rx_handler_count = 1;
    }
    if (xconf->generator_args && xconf->generator_args[0] &&
        xconf->generator->params) {
        if (conf_set_params_from_substr(NULL, xconf->generator->params,
                                        xconf->generator_args)) {
            LOG(LEVEL_ERROR, "sub param parsing of GenerateModule.\n");
            xcmd_try_reboot();
            exit(1);
        }
    }
    if (!xconf->generator->init_cb(xconf, &count_targets, &count_endpoints,
                                   &init_ipv4, &init_ipv6)) {
        LOG(LEVEL_ERROR, "global init of GenerateModule.\n");
        xcmd_try_reboot();
        exit(1);
    }

    LOG(LEVEL_DETAIL, "init_ipv4 from generator: %s\n",
        init_ipv4 ? "true" : "false");
    LOG(LEVEL_DETAIL, "init_ipv6 from generator: %s\n",
        init_ipv6 ? "true" : "false");

    init_ipv4 = xconf->set_ipv4_adapter ? xconf->init_ipv4_adapter : init_ipv4;
    init_ipv6 = xconf->set_ipv6_adapter ? xconf->init_ipv6_adapter : init_ipv6;
    if (!init_ipv4 && !init_ipv6) {
        LOG(LEVEL_ERROR, "neither ipv4 & ipv6 adapter would be inited.\n");
        LOG(LEVEL_HINT, "we can manually init adapter like `-init-ipv4`.\n");
        xcmd_try_reboot();
        exit(1);
    }

    scan_range = count_targets * count_endpoints;

    LOG(LEVEL_DETAIL, "count_targets from generator: %" PRIu64 "\n",
        count_targets);
    LOG(LEVEL_DETAIL, "count_endpoints from generator: %" PRIu64 "\n",
        count_targets);
    LOG(LEVEL_DETAIL, "scan_range from generator: %" PRIu64 "\n", scan_range);

    /**
     * Optimize target again because generator may add new targets.
     */
    targetset_optimize(&xconf->targets);

    /*before rawsock initing*/
    rawsock_prepare();

    /*init NIC & rawsock*/
    if (init_nic(xconf, init_ipv4, init_ipv6) != 0) {
        xcmd_try_reboot();
        exit(1);
    }
    if (!xconf->nic.is_usable) {
        LOG(LEVEL_ERROR, "failed to detect IP of interface\n");
        LOG(LEVEL_HINT, "did you spell the interface name correctly?\n");
        LOG(LEVEL_HINT, "if it has no IP address, "
                        "manually set with \"--adapter-ip 192.168.100.5\"\n");
        xcmd_try_reboot();
        exit(1);
    }

    /*
     * Set the "source ports" of everything we transmit.
     */
    if (xconf->nic.src.port.range == 0) {
        unsigned port             = 40000 + now % 20000;
        xconf->nic.src.port.first = port;
        xconf->nic.src.port.last  = port + XCONF_DFT_PORT_RANGE;
        xconf->nic.src.port.range =
            xconf->nic.src.port.last - xconf->nic.src.port.first;
    }

    /*
     * create callback queue
     */
    xconf->stack = stack_create(xconf->nic.source_mac, &xconf->nic.src,
                                xconf->stack_buf_count);

    /*
     * Initialize the packet templates and attributes
     */
    xconf->tmplset = &tmplset;
    global_tmplset = &tmplset;

    /* it should be set before template init*/
    if (xconf->tcp_init_window)
        template_set_tcp_syn_win_of_default(xconf->tcp_init_window);

    if (xconf->tcp_window)
        template_set_tcp_win_of_default(xconf->tcp_window);

    template_packet_init(xconf->tmplset, xconf->nic.source_mac,
                         xconf->nic.router_mac_ipv4, xconf->nic.router_mac_ipv6,
                         rawsock_if_datalink(xconf->nic.adapter), xconf->seed,
                         xconf->templ_opts);

    if (xconf->packet_ttl)
        template_set_ttl(xconf->tmplset, xconf->packet_ttl);

    if (xconf->nic.is_vlan)
        template_set_vlan(xconf->tmplset, xconf->nic.vlan_id);

    /*
     * Config params & Do global init for ScanModule
     */
    xconf->scanner->probe = xconf->probe;

    if (xconf->scanner_args && xconf->scanner_args[0] &&
        xconf->scanner->params) {
        if (conf_set_params_from_substr(NULL, xconf->scanner->params,
                                        xconf->scanner_args)) {
            LOG(LEVEL_ERROR, "sub param parsing of ScanModule.\n");
            xcmd_try_reboot();
            exit(1);
        }
    }
    if (!xconf->scanner->init_cb(xconf)) {
        LOG(LEVEL_ERROR, "global init of ScanModule.\n");
        xcmd_try_reboot();
        exit(1);
    }

    /*
     * Config params & Do global init for ProbeModule
     */
    if (xconf->probe) {
        if (xconf->probe_args && xconf->probe_args[0] && xconf->probe->params) {
            if (conf_set_params_from_substr(NULL, xconf->probe->params,
                                            xconf->probe_args)) {
                LOG(LEVEL_ERROR, "sub param parsing of ProbeModule.\n");
                xcmd_try_reboot();
                exit(1);
            }
        }

        if (!xconf->probe->init_cb(xconf)) {
            LOG(LEVEL_ERROR, "ProbeModule global initializing\n");
            xcmd_try_reboot();
            exit(1);
        }
    }

    /*
     * Do init for OutputModule
     */
    if (!output_init(xconf, &xconf->out_conf)) {
        LOG(LEVEL_ERROR, "OutputModule initializing\n");
        xcmd_try_reboot();
        exit(1);
    }

    /*
     * BPF filter
     * We set BPF filter for pcap at last to avoid the filter affect router-mac
     * getting by ARP.
     * And the filter string is combined from ProbeModule and user setting.
     */
    if (!xconf->is_no_bpf) {
        rawsock_set_filter(xconf->nic.adapter, xconf->scanner->bpf_filter,
                           xconf->bpf_filter);
    }

    /*
     * trap <ctrl-c>
     */
    signal(SIGINT, _control_c_handler);

    /*
     * Prepare for tx threads
     */
    for (unsigned index = 0; index < xconf->tx_thread_count; index++) {
        TxThread *parms           = &tx_thread[index];
        parms->xconf              = xconf;
        parms->tx_index           = index;
        parms->my_index           = xconf->resume.index;
        parms->done_transmitting  = false;
        parms->thread_handle_xmit = 0;
    }
    /*
     * Prepare for rx thread
     */
    rx_thread->xconf              = xconf;
    rx_thread->done_receiving     = false;
    rx_thread->thread_handle_recv = 0;
    /** needed for --packet-trace option so that we know when we started
     * the scan
     */
    rx_thread->pt_start           = 1.0 * pixie_gettime() / 1000000.0;

    /*
     * prepare meta info file
     */
    if (xconf->meta_filename[0]) {
        int err = pixie_fopen_shareable(&meta_fp, xconf->meta_filename, false);

        if (err != 0 || meta_fp == NULL) {
            LOG(LEVEL_ERROR, "could not open file %s to write meta info.\n",
                xconf->meta_filename);
            LOGPERROR(xconf->meta_filename);
            meta_fp = NULL;
        }
    }

    /*
     * Print meta information before scanning
     */
    char      buffer[80];
    struct tm x;

    now = time(0);
    safe_gmtime(&x, &now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
    LOG(LEVEL_OUT,
        "\nStarting " XTATE_NAME_TITLE_CASE " " XTATE_VERSION " at %s\n",
        buffer);
    LOG(LEVEL_OUT, "(" XTATE_GITHUB_URL ")\n");

    LOG(LEVEL_OUT, "Scanner:    %s\n", xconf->scanner->name);
    if (xconf->probe)
        LOG(LEVEL_OUT, "Probe:      %s\n", xconf->probe->name);
    LOG(LEVEL_OUT, "Generator:  %s\n", xconf->generator->name);
    if (xconf->out_conf.output_module)
        LOG(LEVEL_OUT, "Output:     %s\n", xconf->out_conf.output_module->name);

    LOG(LEVEL_OUT, "Interface:  %s\n", xconf->nic.ifname);
    LOG(LEVEL_OUT, "IP version:");
    if (init_ipv4)
        LOG(LEVEL_OUT, " v4");
    if (init_ipv6)
        LOG(LEVEL_OUT, " v6");
    LOG(LEVEL_OUT, "\n");
    /**
     * We use target and endpoint for generalizing.
     * Not all modules would using host and port. A target can be an IP, URL or
     * any others. An endpoint can be a port, TTL, IP protocol, sub-directory or
     * any others.
     */
    if (count_targets > 0) {
        LOG(LEVEL_OUT, "Scanning %" PRIu64 " targets", count_targets);
        if (count_endpoints > 1) {
            LOG(LEVEL_OUT, " [%" PRIu64 " endpoints each]", count_endpoints);
        }
        if (xconf->shard.of > 1) {
            LOG(LEVEL_OUT, " in shard %u/%u", xconf->shard.one,
                xconf->shard.of);
        }
        LOG(LEVEL_OUT, "\n");
    } else {
        LOG(LEVEL_OUT, "Scanning a dynamic number of targets\n");
    }
    LOG(LEVEL_OUT, "\n");

    /**
     * Print meta information to file before scanning
     */
    while (meta_fp) {
        int err;
        err = fprintf(meta_fp,
                      "Starting " XTATE_WITH_VERSION " at %s\n"
                      "(" XTATE_GITHUB_URL ")\n\n"
                      "Generator: %s\n"
                      "Scanner: %s\n",
                      buffer, xconf->generator->name, xconf->scanner->name);
        if (err < 0)
            goto meta_error0;

        if (xconf->probe) {
            err = fprintf(meta_fp, "Probe: %s\n", xconf->probe->name);
            if (err < 0)
                goto meta_error0;
        }

        if (xconf->out_conf.output_module) {
            err = fprintf(meta_fp, "Output: %s\n",
                          xconf->out_conf.output_module->name);
            if (err < 0)
                goto meta_error0;
        }

        err = fprintf(meta_fp,
                      "Interface: %s\n"
                      "IP version:",
                      xconf->nic.ifname);
        if (err < 0)
            goto meta_error0;

        if (init_ipv4) {
            err = fprintf(meta_fp, " v4");
            if (err < 0)
                goto meta_error0;
        }
        if (init_ipv6) {
            err = fprintf(meta_fp, " v6");
            if (err < 0)
                goto meta_error0;
        }
        err = fprintf(meta_fp, "\n");
        if (err < 0)
            goto meta_error0;
        /**
         * We use target and endpoint for generalizing.
         * Not all modules would using host and port. A target can be an IP, URL
         * or any others. An endpoint can be a port, TTL, IP protocol,
         * sub-directory or any others.
         */
        if (count_targets > 0) {
            err =
                fprintf(meta_fp, "Scanning %" PRIu64 " targets", count_targets);
            if (err < 0)
                goto meta_error0;

            if (count_endpoints > 1) {
                err = fprintf(meta_fp, " [%" PRIu64 " endpoints each]",
                              count_endpoints);
                if (err < 0)
                    goto meta_error0;
            }

            if (xconf->shard.of > 1) {
                err = fprintf(meta_fp, " in shard %u/%u", xconf->shard.one,
                              xconf->shard.of);
                if (err < 0)
                    goto meta_error0;
            }

            err = fprintf(meta_fp, "\n");
            if (err < 0)
                goto meta_error0;
        } else {
            err = fprintf(meta_fp, "Scanning a dynamic number of targets\n");
            if (err < 0)
                goto meta_error0;
        }
        err = fprintf(meta_fp, "\n");
        if (err < 0)
            goto meta_error0;

        break;

    meta_error0:
        LOG(LEVEL_ERROR,
            "could not write before-scanning meta info to file %s\n",
            xconf->meta_filename);
        LOGPERROR(xconf->meta_filename);
        break;
    }

    /*
     * Start tx & rx threads
     */
    rx_thread->thread_handle_recv =
        pixie_begin_thread(receive_thread, 0, rx_thread);
    for (unsigned index = 0; index < xconf->tx_thread_count; index++) {
        TxThread *parms = &tx_thread[index];
        parms->thread_handle_xmit =
            pixie_begin_thread(transmit_thread, 0, parms);
    }

    /**
     * set status outputing
     */
    xtatus_start(&status);
    status.print_queue    = xconf->is_status_queue;
    status.print_info_num = xconf->is_status_info_num;
    status.print_hit_rate = xconf->is_status_hit_rate;
    status.is_infinite    = xconf->is_infinite;
    status.no_ansi        = xconf->is_no_ansi;

    /*
     * Now wait for <ctrl-c> to be pressed OR for Tx Threads to exit.
     * Tx Threads can shutdown by themselves for finishing their tasks.
     * We also can use <ctrl-c> to make them exit early.
     * All controls are decided by global variable `time_to_finish_tx`.
     */
    pixie_usleep(1000 * 100);
    LOG(LEVEL_INFO, "waiting for threads to finish\n");
    global_update_time();
    while (!pixie_locked_fetch_u32(&time_to_finish_tx)) {
        /* Find the min-index, repeat and rate */
        status_item.total_sent   = 0;
        status_item.cur_pps      = 0.0;
        status_item.cur_count    = UINT64_MAX;
        status_item.repeat_count = UINT64_MAX;
        stop_tx                  = true;
        for (unsigned i = 0; i < xconf->tx_thread_count; i++) {
            TxThread *parms = &tx_thread[i];

            if (status_item.cur_count >
                pixie_locked_fetch_u64(&parms->my_index))
                status_item.cur_count =
                    pixie_locked_fetch_u64(&parms->my_index);

            if (status_item.repeat_count >
                pixie_locked_fetch_u64(&parms->my_repeat))
                status_item.repeat_count =
                    pixie_locked_fetch_u64(&parms->my_repeat);

            status_item.cur_pps +=
                pixie_locked_fetch_double(&parms->throttler->current_rate);
            status_item.total_sent +=
                pixie_locked_fetch_u64(&parms->total_sent);

            stop_tx &= (!xconf->generator->hasmore_cb(
                i, pixie_locked_fetch_u64(&parms->my_index)));
        }

        /**
         * Rx handle queue is the bottle-neck, we got the most severe one.
         */
        status_item.rx_queue_ratio = 100.0;
        for (unsigned i = 0; i < xconf->rx_handler_count; i++) {
            if (rx_thread->handle_q && rx_thread->handle_q[i]) {
                rx_free_entries = rte_ring_free_count(rx_thread->handle_q[i]);
            } else {
                rx_free_entries = 0;
            }
            rx_queue_ratio_tmp =
                rx_free_entries * 100.0 / (double)(xconf->dispatch_buf_count);

            if (status_item.rx_queue_ratio > rx_queue_ratio_tmp)
                status_item.rx_queue_ratio = rx_queue_ratio_tmp;
        }

        /**
         * Tx handle queue maybe short if something wrong.
         */
        tx_free_entries = rte_ring_free_count(xconf->stack->transmit_queue);
        status_item.tx_queue_ratio =
            tx_free_entries * 100.0 / (double)xconf->stack_buf_count;

        /* Note: This is how we tell the Tx has ended */
        if (xconf->is_infinite) {
            if (xconf->repeat && status_item.repeat_count >= xconf->repeat)
                pixie_locked_cas_u32(&time_to_finish_tx, 1, 0);
        } else {
            if (stop_tx)
                pixie_locked_cas_u32(&time_to_finish_tx, 1, 0);
        }

        /**
         * additional status from scan module
         */
        status_item.add_status[0] = '\0';
        xconf->scanner->status_cb(status_item.add_status);

        /**
         * update other status item fields
         */
        status_item.total_successed =
            pixie_locked_fetch_u64(&xconf->out_conf.total_successed);
        status_item.total_failed =
            pixie_locked_fetch_u64(&xconf->out_conf.total_failed);
        status_item.total_info =
            pixie_locked_fetch_u64(&xconf->out_conf.total_info);
        status_item.max_count     = scan_range;
        status_item.print_in_json = xconf->is_status_ndjson;

        if (!xconf->is_no_status)
            xtatus_print(&status, &status_item);

        /**
         * Update global time and sleep less than 1 sec.
         * NOTE: ths sleep time decides the accuracy of the global time variable
         * because we update it periodically in loops.
         */

        global_update_time();
        pixie_mssleep(_LOOP_SLEEP_MS);
    }

    /*
     * If we haven't completed the scan, then save the resume
     * information.
     */
    if (status_item.cur_count < scan_range && !xconf->is_infinite &&
        !xconf->is_noresume) {
        xconf->resume.index = status_item.cur_count;
        LOG(LEVEL_HINT, "saving resume file to: %s\n",
            XCONF_DFT_RESUME_FILENAME);
        xconf_save_conf(xconf, XCONF_DFT_RESUME_FILENAME);
    }

    /*
     * Now Tx Threads have breaked out the main loop of sending because of
     * `time_to_finish_tx` and go into loop of `stack_flush_packets` before
     * `time_to_finish_rx`. Rx Thread exits just by our setting of
     * `time_to_finish_rx` according to time waiting. So `time_to_finish_rx` is
     * the important signal both for Tx/Rx Thread to exit.
     */
    global_update_time();
    now = global_get_time();
    for (;;) {
        /* Find the min-index, repeat and rate */
        status_item.total_sent   = 0;
        status_item.cur_pps      = 0.0;
        status_item.cur_count    = UINT64_MAX;
        status_item.repeat_count = UINT64_MAX;
        for (unsigned i = 0; i < xconf->tx_thread_count; i++) {
            TxThread *parms = &tx_thread[i];

            if (status_item.cur_count >
                pixie_locked_fetch_u64(&parms->my_index))
                status_item.cur_count =
                    pixie_locked_fetch_u64(&parms->my_index);

            if (status_item.repeat_count >
                pixie_locked_fetch_u64(&parms->my_repeat))
                status_item.repeat_count =
                    pixie_locked_fetch_u64(&parms->my_repeat);

            status_item.cur_pps +=
                pixie_locked_fetch_double(&parms->throttler->current_rate);
            status_item.total_sent +=
                pixie_locked_fetch_u64(&parms->total_sent);
        }

        /**
         * Rx handle queue is the bottle-neck, we got the most severe one.
         */
        status_item.rx_queue_ratio = 100.0;
        for (unsigned i = 0; i < xconf->rx_handler_count; i++) {
            if (rx_thread->handle_q && rx_thread->handle_q[i]) {
                rx_free_entries = rte_ring_free_count(rx_thread->handle_q[i]);
            } else {
                rx_free_entries = 0;
            }
            rx_queue_ratio_tmp =
                rx_free_entries * 100.0 / (double)(xconf->dispatch_buf_count);

            if (status_item.rx_queue_ratio > rx_queue_ratio_tmp)
                status_item.rx_queue_ratio = rx_queue_ratio_tmp;
        }

        /**
         * Tx handle queue maybe short if something wrong.
         */
        tx_free_entries = rte_ring_free_count(xconf->stack->transmit_queue);
        status_item.tx_queue_ratio =
            tx_free_entries * 100.0 / (double)xconf->stack_buf_count;

        /**
         * additional status from scan module
         */
        status_item.add_status[0] = '\0';
        xconf->scanner->status_cb(status_item.add_status);

        /**
         * update other status item fields
         */
        status_item.total_successed =
            pixie_locked_fetch_u64(&xconf->out_conf.total_successed);
        status_item.total_failed =
            pixie_locked_fetch_u64(&xconf->out_conf.total_failed);
        status_item.total_info =
            pixie_locked_fetch_u64(&xconf->out_conf.total_info);
        status_item.max_count     = scan_range;
        status_item.print_in_json = xconf->is_status_ndjson;
        status_item.exiting_secs  = xconf->wait - (time(0) - now);

        if (!xconf->is_no_status)
            xtatus_print(&status, &status_item);

        /* An output sink exhausted its retries. Stop scanning and report a
         * non-zero exit instead of silently losing more results. */
        if (output_has_fatal_error()) {
            LOG(LEVEL_ERROR,
                "output sink failed after retries; stopping scan\n");
            pixie_locked_cas_u32(&time_to_finish_tx, 1, 0);
            pixie_locked_cas_u32(&time_to_finish_rx, 1, 0);
            break;
        }

        /*no more waiting or too many <ctrl-c>*/
        if (time(0) - now >= xconf->wait ||
            pixie_locked_fetch_u32(&time_to_finish_rx)) {
            LOG(LEVEL_DEBUG, "telling threads to exit...\n");
            pixie_locked_cas_u32(&time_to_finish_rx, 1, 0);
            break;
        }

        /**
         * Update global time and sleep less than 1 sec.
         * NOTE: ths sleep time decides the accuracy of the global time variable
         * because we update it periodically in loops.
         */
        global_update_time();
        pixie_mssleep(_LOOP_SLEEP_MS);
    }

    /*
     * untrap <ctrl-c>
     */
    signal(SIGINT, SIG_DFL);

    global_update_time();
    for (unsigned i = 0; i < xconf->tx_thread_count; i++) {
        TxThread *parms = &tx_thread[i];
        pixie_thread_join(parms->thread_handle_xmit);
    }

    global_update_time();
    pixie_thread_join(rx_thread->thread_handle_recv);

    /*
     * Print meta information after scanning
     */
    uint64_t usec_now = pixie_gettime();
    LOG(LEVEL_OUT,
        "\n%u milliseconds elapsed: [+]=%" PRIu64 " [x]=%" PRIu64
        " [*]=%" PRIu64 "\n",
        (unsigned)((usec_now - _usec_start) / 1000),
        status_item.total_successed, status_item.total_failed,
        status_item.total_info);

    /**
     * Print meta information to file before scanning
     */
    while (meta_fp) {
        int err;
        err = fprintf(meta_fp,
                      "scanning duration = %ums\n"
                      "successful results = %" PRIu64 "\n"
                      "failed results = %" PRIu64 "\n"
                      "information results = %" PRIu64 "\n",
                      (unsigned)((usec_now - _usec_start) / 1000),
                      status_item.total_successed, status_item.total_failed,
                      status_item.total_info);
        if (err < 0)
            goto meta_error1;

        break;

    meta_error1:
        LOG(LEVEL_ERROR,
            "could not write after-scanning meta info to file %s\n",
            xconf->meta_filename);
        LOGPERROR(xconf->meta_filename);
        break;
    }

    if (meta_fp) {
        fclose(meta_fp);
        meta_fp = NULL;
    }

    /*
     * Now cleanup everything
     */
    xtatus_finish(&status);

    xconf->scanner->close_cb();

    if (xconf->probe) {
        xconf->probe->close_cb();
    }

    xconf->generator->close_cb();

    output_close(&xconf->out_conf);

    FREE(tx_thread);

    rawsock_close_adapter(xconf->nic.adapter);

    stack_clear(xconf->stack);

    template_packet_clear(xconf->tmplset);
    FREE(xconf->templ_opts);

    LOG(LEVEL_INFO, "all threads exited...\n");

    return output_has_fatal_error() ? 1 : 0;
}

/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[]) {

    int err;

    /*init logger at first*/
    LOG_init();
    i18n_init();

    XConf xconf[1];
    memset(xconf, 0, sizeof(XConf));

#if defined(_WIN32)
    {
        WSADATA x;
        WSAStartup(0x101, &x);
    }
#endif

    /* Set system to report debug information on crash */
    int is_backtrace = 1;
    for (unsigned i = 1; i < (unsigned)argc; i++) {
        if (argv[i][0] == '-' && (conf_equals(argv[i] + 1, "no-backtrace") ||
                                  conf_equals(argv[i] + 1, "no-bt"))) {
            is_backtrace = 0;
        }
    }
    if (is_backtrace) {
        pixie_backtrace_init(argv[0]);
    } else {
        LOG(LEVEL_WARN, "backtrace to program call stack is off.\n");
    }

    // Define default params
    xconf_global_refresh(xconf);

    // read conf from args
    err = xconf_command_line(xconf, argc, argv);
    if (err) {
        LOG(LEVEL_ERROR, "failed to parse cmdline parameters.\n");
        xcmd_try_reboot();
        exit(1);
    }

    /* entropy for randomness */
    if (xconf->seed == 0)
        xconf->seed = get_one_entropy();

    /* into interactive setting mode*/
    if (xconf->interactive_mode) {
        xcmd_interactive_readline(xconf, argv[0]);
    }

    /* logger should be prepared early */
    LOG_set_ansi(xconf->is_no_ansi);

    /* init AS info for global and output module*/
    xconf->as_query =
        as_query_new(xconf->ip2asn_v4_filename, xconf->ip2asn_v6_filename);
    xconf->out_conf.as_query = xconf->as_query;

    /**
     * Add target by ASN
     */
    if (xconf->target_asn_v4) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv4 target by ASN because no AS info loaded.\n");
            xcmd_try_reboot();
            exit(1);
        }
        err = targetset_add_asn4_str(&xconf->targets, xconf->as_query,
                                     xconf->target_asn_v4);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv4 target failed by ASN string.\n");
            xcmd_try_reboot();
            exit(1);
        }
    }
    if (xconf->target_asn_v6) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv6 target by ASN because no AS info loaded.\n");
            xcmd_try_reboot();
            exit(1);
        }
        err = targetset_add_asn6_str(&xconf->targets, xconf->as_query,
                                     xconf->target_asn_v6);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv6 target failed by ASN string.\n");
            xcmd_try_reboot();
            exit(1);
        }
    }

    /**
     * Add exclude target by ASN
     */
    if (xconf->exclude_asn_v4) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv4 exclude by ASN because no AS info loaded.\n");
            xcmd_try_reboot();
            exit(1);
        }
        err = targetset_add_asn4_str(&xconf->exclude, xconf->as_query,
                                     xconf->exclude_asn_v4);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv4 exclude failed by ASN string.\n");
            xcmd_try_reboot();
            exit(1);
        }
    }
    if (xconf->exclude_asn_v6) {
        if (xconf->as_query == NULL) {
            LOG(LEVEL_ERROR,
                "cannot add ipv6 exclude by ASN because no AS info loaded.\n");
            xcmd_try_reboot();
            exit(1);
        }
        err = targetset_add_asn6_str(&xconf->exclude, xconf->as_query,
                                     xconf->exclude_asn_v6);
        if (err) {
            LOG(LEVEL_ERROR, "add ipv6 exclude failed by ASN string.\n");
            xcmd_try_reboot();
            exit(1);
        }
    }

    targetset_apply_excludes(&xconf->targets, &xconf->exclude);

    /**
     * Optimize target set so that continuous code could get count or searching
     * directly.
     * */
    targetset_optimize(&xconf->targets);

    /**
     * Begin to update time
     */
    _usec_start = pixie_gettime();
    global_update_time();

    int exit_code = 0;

    switch (xconf->op) {
        /* interactive mode should avoid this case for better printing */
        case Op_Default:
            xconf_print_banner();
            break;

        case Op_Scan:
            exit_code = _main_scan(xconf);
            break;

        case Op_Echo:
            xconf_echo(xconf, stdout);
            break;

        case Op_DebugIF:
            rawsock_selftest_if(xconf->nic.ifname);
            break;

        case Op_ListCidr:
            listtargets_cidr(xconf, stdout);
            break;

        case Op_ListRange:
            listtargets_range(xconf, stdout);
            break;

        case Op_ListTargets:
            listtargets_ip_port(xconf, stdout);
            break;

        case Op_ListAdapters:
            rawsock_list_adapters();
            break;

        case Op_ListScanModules:
            list_all_scan_modules();
            break;

        case Op_HelpScanModule:
            help_scan_module(xconf->scanner);
            break;

        case Op_ListProbeModules:
            list_all_probe_modules();
            break;

        case Op_HelpProbeModule:
            help_probe_module(xconf->probe);
            break;

        case Op_ListOutputModules:
            list_all_output_modules();
            break;

        case Op_HelpOutputModule:
            help_output_module(xconf->out_conf.output_module);
            break;

        case Op_ListGenerateModules:
            list_all_generate_modules();
            break;

        case Op_HelpGenerateModule:
            help_generate_module(xconf->generator);
            break;

        case Op_PrintUsage:
            xconf_print_usage();
            break;

        case Op_PrintHelp:
            xconf_print_help();
            break;

        case Op_PrintIntro:
            xconf_print_intro();
            break;

        case Op_PrintVersion:
            xconf_print_version();
            break;

        case Op_HelpParam:
            xconf_help_param(xconf->help_param);
            break;

        case Op_SearchParam:
            xconf_search_param(xconf->search_param);
            break;

        case Op_SearchModule:
            xconf_search_module(xconf->search_module);
            break;

        case Op_Selftest:
            exit_code = xconf_selftest();
            break;

        case Op_Benchmark:
            xconf_benchmark(XCONF_DFT_BLACKROCK_ROUNDS);
            break;

#ifndef NOT_FOUND_BSON
        case Op_ParseBson:
            parse_bson_file(xconf->parse_bson_file);
            break;
#endif

#ifndef NOT_FOUND_MONGOC
        case Op_StoreBson:
            store_bson_file(xconf->store_bson_file, xconf->mongodb_uri,
                            xconf->mongodb_db, xconf->mongodb_col,
                            xconf->mongodb_app);
            break;

        case Op_StoreJson:
            store_json_file(xconf->store_json_file, xconf->mongodb_uri,
                            xconf->mongodb_db, xconf->mongodb_col,
                            xconf->mongodb_app);
            break;
#endif

#ifndef NOT_FOUND_PCRE2
        case Op_ListNmapProbes:
            nmapservice_print_probes_by_file(xconf->nmap_file, stdout);
            break;
#endif
    }

    if (output_has_fatal_error())
        exit_code = 1;

    /*close logger*/
    LOG_close();

    xconf_global_refresh(xconf);

    xcmd_try_reboot();

    return exit_code;
}
