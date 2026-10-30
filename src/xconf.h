#ifndef XCONF_H
#define XCONF_H

#include <stdio.h>
#include <stdint.h>

#include "target/target-ipaddress.h"
#include "target/target-set.h"

#include "stack/stack-src.h"
#include "stack/stack-queue.h"

#include "generate-modules/generate-modules.h"
#include "output-modules/output-modules.h"
#include "probe-modules/probe-modules.h"
#include "scan-modules/scan-modules.h"

#include "templ/templ-opts.h"
#include "templ/templ-pkt.h"

#include "as/as-query.h"
#include "rawsock/rawsock.h"

/**
 * some default config
 */
/* 14 rounds seem to give way better statistical distribution than 4 with a
very low impact on scan rate */
#define XCONF_DFT_BLACKROCK_ROUNDS   14
#define XCONF_DFT_TX_THD_COUNT       1
#define XCONF_DFT_RX_HDL_COUNT       1
#define XCONF_DFT_STACK_BUF_COUNT    16384
#define XCONF_DFT_DISPATCH_BUF_COUNT 16384
#define XCONF_DFT_MAX_RATE           100.0
#define XCONF_DFT_DEDUP_WIN          1000000
#define XCONF_DFT_SHARD_ONE          1
#define XCONF_DFT_SHARD_OF           1
#define XCONF_DFT_WAIT               10
#define XCONF_DFT_PORT_RANGE         256
#define XCONF_DFT_SNAPLEN            65535 /*also the max*/
#define XCONF_DFT_MAX_PKT_LEN        1514
#define XCONF_DFT_PACKET_TTL         128
#define XCONF_DFT_TCP_SYN_WINSIZE    64240
#define XCONF_DFT_TCP_OTHER_WINSIZE  1024
#define XCONF_DFT_SENDMMSG_BATCH     64
#define XCONF_DFT_SENDMMSG_RETRIES   10
#define XCONF_DFT_SENDQUEUE_SIZE     (65535 * 8)
#define XCONF_DFT_RESUME_FILENAME    "resume.conf"  /*paused while scanning*/
#define XCONF_DFT_RECOVER_FILENAME   "recover.conf" /*for interact mode*/

enum Operation {
    Op_Default = 0,         /* nothing specified, so print usage */
    Op_Scan,                /* do scan */
    Op_Echo,                /* echo the config or all configs with --echo-all */
    Op_DebugIF,             /* do special selftest to interface for debugging*/
    Op_ListCidr,            /* list all target IPs in CIDR */
    Op_ListRange,           /* list all target IPs in range */
    Op_ListTargets,         /* list all target in IPs and Ports*/
    Op_ListAdapters,        /* list all usable interfaces */
    Op_ListScanModules,     /* list all scan modules */
    Op_HelpScanModule,      /* print help of specified scan module */
    Op_ListProbeModules,    /* list all probes */
    Op_HelpProbeModule,     /* print help of specified probe module */
    Op_ListOutputModules,   /* list all probes */
    Op_HelpOutputModule,    /* print help of specified output module */
    Op_ListGenerateModules, /* list all generate modules */
    Op_HelpGenerateModule,  /* print help of specified generate module */
    Op_PrintUsage,          /* print usage examples*/
    Op_PrintHelp,           /* print help text for all parameters*/
    Op_PrintIntro,          /* print introduction text of work flow*/
    Op_PrintVersion,        /* print version and build info*/
    Op_HelpParam,           /* print help text for specific param*/
    Op_SearchParam,         /* fuzzy searching for specific param*/
    Op_SearchModule,        /* fuzzy searching for specific module*/
    Op_Selftest,            /* do global regression test*/
    Op_Benchmark,           /* do global benchmark for key units */
#ifndef NOT_FOUND_BSON
    Op_ParseBson, /*parse BSON result file to JSON format*/
#endif
#ifndef NOT_FOUND_MONGOC
    Op_StoreBson, /*store BSON result file to MongoDB*/
    Op_StoreJson, /*store NDJSON result file to MongoDB*/
#endif
#ifndef NOT_FOUND_PCRE2
    Op_ListNmapProbes, /* list all nmap probes */
#endif
};

struct source_t {
    unsigned    ipv4;
    unsigned    ipv4_mask;
    unsigned    port;
    unsigned    port_mask;
    ipv6address ipv6;
    uint64_t    ipv6_mask;
};

/**
 * Once read in at the start, this structure doesn't change unless we know what
 * is happenning.
 * The transmit and receive threads have only a "const" pointer to this
 * structure.
 */
typedef struct XtateConf {
    /**
     * Just one network adapters that we'll use for scanning. Adapter
     * should have a set of IP source addresses, except in the case
     * of PF_RING dnaX:Y adapters.
     */
    struct {
        char          ifname[256];
        Adapter      *adapter;
        StackSrc      src;
        macaddress_t  source_mac;
        macaddress_t  router_mac_ipv4;
        macaddress_t  router_mac_ipv6;
        ipv4address_t router_ip;
        unsigned      vlan_id;
        unsigned      snaplen;
        int           link_type;
        unsigned char my_mac_count;
        unsigned      is_vlan   : 1;
        unsigned      is_usable : 1;
    } nic;

    /**save resume info */
    struct {
        uint64_t index;
        /** Derives the --resume-index from the target ip:port */
        struct {
            unsigned ip;
            unsigned port;
        } target;
    } resume;
    /**
     * for dividing task into shards
     * */
    struct {
        unsigned one;
        unsigned of;
    } shard;
    /**
     * save scanning targets(ip*port).
     * but generator may not use this.
     * */
    TargetSet        targets;
    TargetSet        exclude;
    /**
     * Temporary file to echo parameters to, used for saving configuration
     * to a file
     */
    FILE            *echo;
    unsigned         echo_all;
    /**
     * info of the abstract whole network tx/rx stack
     * */
    NetStack        *stack;
    unsigned         stack_buf_count;
    /**
     * PCAP info
     * */
    char            *bpf_filter;
    char             pcap_filename[256];
    /**
     * meta info file
     * */
    char             meta_filename[256];
    /**
     * template for packet making quickly.
     */
    TmplSet         *tmplset;
    TmplOpt         *templ_opts;
    /**
     * probe module
     * */
    Probe           *probe;
    char            *probe_args;
    /**
     * scan module
     * */
    Scanner         *scanner;
    char            *scanner_args;
    /**
     * generate module
     * */
    Generator       *generator;
    char            *generator_args;
    /**
     * output module
     * */
    OutConf          out_conf;
    /**
     * We could set the number of transmit threads.
     * NOTE: Always only one receiving thread for consistency of dedup, timeout
     * and packets recording....
     * But, we have recv-handlers in multi threads to exec handle_cb of
     * ScanModule. Now we could set the number of recv-handlers in the power
     * of 2.
     */
    unsigned         tx_thread_count;
    unsigned         rx_handler_count;
    /**
     * AS info from ip2asn files
     */
    struct AS_Query *as_query;
    char            *ip2asn_v4_filename;
    char            *ip2asn_v6_filename;
    char            *target_asn_v4;
    char            *target_asn_v6;
    char            *exclude_asn_v4;
    char            *exclude_asn_v6;
    /**
     * param help
     */
    char            *help_param;
    char            *search_param;
    char            *search_module;
    /**
     * other switches
     * */
    enum Operation   op;
    uint64_t         seed;
    uint64_t         repeat;
    double           max_rate;
    unsigned         wait;
    unsigned         dedup_win;
    unsigned         dispatch_buf_count;
    uint64_t         tcb_count;
    unsigned         tcp_init_window;
    unsigned         tcp_window;
    unsigned         packet_ttl;
    unsigned         max_packet_len;
    unsigned         sendq_size;
    unsigned         sendmmsg_batch;
    unsigned         sendmmsg_retries;
    unsigned         is_packet_trace      : 1;
    unsigned         is_no_ansi           : 1;
    unsigned         is_no_status         : 1;
    unsigned         is_status_ndjson     : 1;
    unsigned         is_status_queue      : 1;
    unsigned         is_status_info_num   : 1;
    unsigned         is_status_hit_rate   : 1;
    unsigned         is_pfring            : 1;
    unsigned         is_rawsocket         : 1;
    unsigned         is_sendmmsg          : 1;
    unsigned         is_sendq             : 1;
    unsigned         is_offline           : 1;
    unsigned         is_nodedup           : 1;
    unsigned         is_noresume          : 1;
    unsigned         is_infinite          : 1;
    unsigned         is_bypass_os         : 1;
    unsigned         is_no_bpf            : 1;
    unsigned         is_no_cpu_bind       : 1;
    unsigned         is_static_seed       : 1;
    unsigned         no_escape_char       : 1;
    unsigned         set_ipv4_adapter     : 1;
    unsigned         set_ipv6_adapter     : 1;
    unsigned         init_ipv4_adapter    : 1;
    unsigned         init_ipv6_adapter    : 1;
    unsigned         listtargets_in_order : 1;
    unsigned         interactive_mode     : 1;
    unsigned         have_read_conf       : 1;

    /**
     * parse BSON file
     */
#ifndef NOT_FOUND_BSON
    char *parse_bson_file;
#endif
    /**
     * store BSON file to MongoDB
     */
#ifndef NOT_FOUND_MONGOC
    char *store_json_file;
    char *store_bson_file;
    char *mongodb_uri;
    char *mongodb_db;
    char *mongodb_col;
    char *mongodb_app;
#endif
    /**
     * list nmap probes
     */
#ifndef NOT_FOUND_PCRE2
    char *nmap_file;
#endif
} XConf;

/**
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 *
 * @return zero if success.
 */
int xconf_command_line(XConf *xconf, int argc, char *argv[]);

/**
 * read configuration from specified file.
 * @return zero if successed.
 */
int xconf_read_conf(XConf *xconf, const char *filename);

/**
 * save current configuration to specified file.
 * @return zero if successed.
 */
int xconf_save_conf(XConf *xconf, const char *filename);

/**
 * Pre-scan the command-line looking for options that may affect how
 * previous options are handled. This is a bit of a kludge, really.
 */
bool xconf_contains(const char *x, int argc, char **argv);

/**
 * set a parameter by "key=value" string style
 * @return zero if successed, -1 if setting error, 1 if comments, 2 if invalid
 * format.
 */
int xconf_set_parameter_in_kv(XConf *xconf, char *line, size_t len);

/**
 * Called to set a <name=value> pair.
 * @return non-zero if err
 */
int xconf_set_parameter(XConf *xconf, const char *name, const char *value);

/**
 * Echoes the settings to the command-line. By default, echoes only
 * non-default values. With "echo-all", everything is echoed.
 */
void xconf_echo(XConf *xconf, FILE *fp);

void xconf_print_intro();

void xconf_print_banner();

void xconf_print_usage();

void xconf_print_help();

void xconf_print_version();

void xconf_help_param(const char *param);

void xconf_search_param(const char *param);

void xconf_search_module(const char *param);

/**
 * Clear global used param in `main` except seed and set xconf to default
 */
void xconf_global_refresh(XConf *xconf);

int xconf_selftest(void);

void xconf_benchmark(unsigned blackrock_rounds);

#endif
