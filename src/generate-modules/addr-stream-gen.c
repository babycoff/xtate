#include "generate-modules.h"

#include "../xconf.h"
#include "../util-data/file-open.h"
#include "stream-reader.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../target/target-cookie.h"
#include "../target/target-set.h"
#include "../target/target-rangev4.h"
#include "../target/target-rangev6.h"
#include "../target/target-rangeport.h"
#include "../crypto/crypto-blackrock.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

Generator AddrStreamGen;

struct AddrStreamConf {
    FILE     *fp;
    uint64_t  seed;
    TargetSet targets;
    uint64_t  index;
    uint64_t  range_all;
    BlackRock br_table;
    unsigned  rounds;
    char      splitter[10];
    size_t    splitter_len;
    unsigned  no_random : 1;
    char     *filename;
    uint64_t  line_number;
    uint64_t  bad_lines;
};

static struct AddrStreamConf addrstream_conf = {0};

static ConfRes SET_no_random(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    addrstream_conf.no_random = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_splitter(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    safe_strcpy(addrstream_conf.splitter, sizeof(addrstream_conf.splitter),
                value);
    addrstream_conf.splitter_len = strlen(addrstream_conf.splitter);

    return Conf_OK;
}

static ConfRes SET_rounds(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    addrstream_conf.rounds = (unsigned)conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (addrstream_conf.fp && addrstream_conf.fp != stdin) fclose(addrstream_conf.fp);
    FREE(addrstream_conf.filename);
    addrstream_conf.filename = STRDUP(value);
    addrstream_conf.fp = file_open_utf8(value);
    if (addrstream_conf.fp == NULL) {
        LOG(LEVEL_ERROR, "(stream generator) %s: %s\n", value, strerror(errno));
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfParam addrstream_parameters[] = {
    {"address-file",
     SET_file,
     Type_ARG,
     {"addr-file", "file", "f", 0},
     "Specifies a file as input stream. Default is stdin."},
    {"splitter",
     SET_splitter,
     Type_ARG,
     {"split", 0},
     "Specifies a string as splitter of ip and port range in input stream. "
     "Default splitter is a space."},
    {"rounds",
     SET_rounds,
     Type_ARG,
     {"round", 0},
     "Specifies the number of round in blackrock algorithm for targets "
     "randomization in every IP/Port range. It's 14 rounds in default to give "
     "a better statistical distribution with a low impact on scan rate."},
    {"no-random",
     SET_no_random,
     Type_FLAG,
     {"no-blackrock", "order", 0},
     "Generate targets in natural order instead of using blackrock algorithm "
     "to randomize."},

    {0}};

bool addrstream_init(const XConf *xconf, uint64_t *count_targets,
                     uint64_t *count_endpoints, bool *init_ipv4,
                     bool *init_ipv6) {
    if (xconf->tx_thread_count != 1) {
        LOG(LEVEL_ERROR, "(stream generator) supports only 1 tx thread.\n");
        return false;
    }

    if (addrstream_conf.splitter[0] == '\0') {
        LOG(LEVEL_HINT,
            "(stream generator) use space as splitter for no specified.\n");
        addrstream_conf.splitter[0]  = ' ';
        addrstream_conf.splitter_len = 1;
    }

    if (!addrstream_conf.fp) {
        addrstream_conf.fp = stdin;
    }

    if (addrstream_conf.rounds <= 0) {
        addrstream_conf.rounds = XCONF_DFT_BLACKROCK_ROUNDS;
    }

    /*init all adapter in default*/
    *init_ipv4 = true;
    *init_ipv6 = true;

    addrstream_conf.seed = xconf->seed;

    return true;
}

bool addrstream_hasmore(unsigned tx_index, uint64_t index) {

    if (addrstream_conf.index < addrstream_conf.range_all)
        return true;

    /*remove old ips */
    TargetSet *cur_tgt = &addrstream_conf.targets;
    targetset_rm_all(cur_tgt);

    /*add new ips*/
    char line[256];
    while (true) {
        bool too_long = false;
        int rr = stream_read_line(addrstream_conf.fp, line, sizeof(line),
                                  addrstream_conf.filename,
                                  &addrstream_conf.line_number,
                                  &addrstream_conf.bad_lines, &too_long);
        if (rr < 0) {
            if (ferror(addrstream_conf.fp))
                LOG(LEVEL_ERROR, "%s: read error\n",
                    addrstream_conf.filename ? addrstream_conf.filename : "<stdin>");
            else
                LOG(LEVEL_DEBUG, "(stream generator) EOF of stream.\n");
            return false;
        }
        char *s = line;
        if (rr > 0) {
            LOG(LEVEL_ERROR, "%s:%llu: target line too long (max %zu bytes)\n",
                addrstream_conf.filename ? addrstream_conf.filename : "<stdin>",
                (unsigned long long)addrstream_conf.line_number,
                sizeof(line) - 1);
            continue;
        }
        /*absolute null line or the last line*/
        if (s[0] == '\n' || s[0] == '\r') {
            continue;
        }

        /*split ip range and port range*/
        char *sub = strstr(s, addrstream_conf.splitter);
        if (sub == NULL) {
            LOG(LEVEL_ERROR,
                "(stream generator) invalid splitter in address: %s", line);
            continue;
        }

        sub[0]         = '\0';
        char *port_str = sub + addrstream_conf.splitter_len;

        int err = targetset_add_ip_str(cur_tgt, s);
        if (err) {
            sub[0] = addrstream_conf.splitter[0];
            LOG(LEVEL_ERROR, "(stream generator) invalid ip in address: %s",
                line);
            continue;
        }

        err = targetset_add_port_str(cur_tgt, port_str, 0);
        if (err) {
            sub[0] = addrstream_conf.splitter[0];
            LOG(LEVEL_ERROR, "(stream generator) invalid port in address: %s",
                line);
            targetset_rm_ip(cur_tgt);
            continue;
        }

        /**
         * port range may not be added, so check it earlier.
         */
        targetset_optimize(cur_tgt);

        if (cur_tgt->count_ports == 0) {
            sub[0] = addrstream_conf.splitter[0];
            LOG(LEVEL_ERROR, "(stream generator) not valid port in address: %s",
                line);
            targetset_rm_ip(cur_tgt);
            continue;
        }

        /**
         * !only support 63-bit scans for every line
         */
        if (int128_bitcount(targetset_count(cur_tgt)) > 63) {
            LOG(LEVEL_ERROR,
                "(stream generator) range too large for scanning: "
                "%u-bits(>63).\n",
                int128_bitcount(targetset_count(cur_tgt)));
            continue;
        }

        break;
    }

    /*update relevant info*/

    addrstream_conf.range_all =
        (cur_tgt->count_ipv4s + cur_tgt->count_ipv6s.lo) * cur_tgt->count_ports;
    addrstream_conf.index = 0;

    /*init blackrock again*/
    if (!addrstream_conf.no_random)
        blackrock1_init(&addrstream_conf.br_table, addrstream_conf.range_all,
                        addrstream_conf.seed, addrstream_conf.rounds);

    return true;
}

Target addrstream_generate(unsigned tx_index, uint64_t index, uint64_t repeat,
                           struct source_t *src) {
    Target     target;
    TargetSet *cur_tgt = &addrstream_conf.targets;
    uint64_t   xXx     = addrstream_conf.index;
    uint64_t   ck;

    /*Actually it is impossible*/
    while (xXx >= addrstream_conf.range_all) {
        xXx -= addrstream_conf.range_all;
    }

    if (!addrstream_conf.no_random)
        xXx = blackrock1_shuffle(&addrstream_conf.br_table, xXx);

    /**
     * Pick up target & source
     */
    if (xXx < cur_tgt->ipv4_threshold) {
        target.ip_them.version = 4;
        target.ip_me.version   = 4;

        target.ip_them.ipv4 =
            rangelist_pick(&cur_tgt->ipv4, xXx % cur_tgt->count_ipv4s);
        target.port_them =
            rangelist_pick(&cur_tgt->ports, xXx / cur_tgt->count_ipv4s);

        if (src->ipv4_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), addrstream_conf.seed);
            target.port_me    = src->port + (ck & src->port_mask);
            target.ip_me.ipv4 = src->ipv4 + ((ck >> 16) & src->ipv4_mask);
        } else {
            target.port_me    = src->port;
            target.ip_me.ipv4 = src->ipv4;
        }
    } else {
        xXx -= cur_tgt->ipv4_threshold;

        target.ip_them.version = 6;
        target.ip_me.version   = 6;

        target.ip_them.ipv6 =
            range6list_pick(&cur_tgt->ipv6, xXx % cur_tgt->count_ipv6s.lo);
        target.port_them =
            rangelist_pick(&cur_tgt->ports, xXx / cur_tgt->count_ipv6s.lo);

        target.ip_me.ipv6 = src->ipv6;

        if (src->ipv6_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)xXx, (unsigned)(xXx >> 32), addrstream_conf.seed);
            target.port_me = src->port + (ck & src->port_mask);
            target.ip_me.ipv6.lo += (ck & src->ipv6_mask);
        } else {
            target.port_me = src->port;
        }
    }

    /**
     * Due to flexible port store method.
     */
    target.ip_proto = get_actual_proto_port(&target.port_them);

    addrstream_conf.index++;

    return target;
}

void addrstream_close() {
    if (addrstream_conf.fp != stdin) {
        fclose(addrstream_conf.fp);
    }
    addrstream_conf.fp = NULL;
    targetset_rm_all(&addrstream_conf.targets);
}

Generator AddrStreamGen = {
    .name   = "addr-stream",
    .params = addrstream_parameters,
    .short_desc =
        "Generates targets by IP/Port range pairs from stdin or file stream.",
    .desc = "AddrStream module generates target from stdin or file stream. The "
            "stream contains IP/Port range pair in lines. Default splitter of "
            "ip and port range is a space. For every IP/Port range pair(line), "
            "AddrStream will do random picking by blackrock algorithm.\n"
            "NOTE: AddrStream will blocking the tx thread while waiting the "
            "stream to be readable, this would break the rule of scan rate. "
            "However, the scan rate won't exceed the configured value.",

    .init_cb     = &addrstream_init,
    .hasmore_cb  = &addrstream_hasmore,
    .generate_cb = &addrstream_generate,
    .close_cb    = &addrstream_close,
};
