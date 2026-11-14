#include "generate-modules.h"

#include <string.h>

#include "../xconf.h"
#include "../util-data/file-open.h"
#include "stream-reader.h"
#include "../util-data/fine-malloc.h"
#include "../target/target-cookie.h"
#include "../target/target-set.h"
#include "../target/target-rangev4.h"
#include "../target/target-rangev6.h"
#include "../target/target-rangeport.h"
#include "../crypto/crypto-blackrock.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

Generator IpStreamGen;

struct IpStreamConf {
    FILE     *fp;
    uint64_t  seed;
    TargetSet targets;
    uint64_t  index;
    uint64_t  range_all;
    BlackRock br_table;
    unsigned  rounds;
    unsigned  no_random : 1;
    char     *filename;
    uint64_t  line_number;
    uint64_t  bad_lines;
    uint64_t  valid_lines;
    bool      strict_errors;
    uint64_t  max_errors;
    unsigned  max_error_percent;
};

static struct IpStreamConf ipstream_conf = {0};

static ConfRes SET_no_random(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ipstream_conf.no_random = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_rounds(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ipstream_conf.rounds = (unsigned)conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_port(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    int err = targetset_add_port_str(&ipstream_conf.targets, value, 0);
    if (err) {
        LOG(LEVEL_ERROR, "(stream generator) invalid port: %s.\n", value);
        return Conf_ERR;
    }
    rangelist_optimize(&ipstream_conf.targets.ports);
    ipstream_conf.targets.count_ports =
        rangelist_count(&ipstream_conf.targets.ports);

    return Conf_OK;
}

static ConfRes SET_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (ipstream_conf.fp && ipstream_conf.fp != stdin) fclose(ipstream_conf.fp);
    FREE(ipstream_conf.filename);
    ipstream_conf.filename = STRDUP(value);
    ipstream_conf.fp = file_open_utf8(value);
    if (ipstream_conf.fp == NULL) {
        LOG(LEVEL_ERROR, "(stream generator) %s: %s\n", value, strerror(errno));
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfRes SET_strict(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    ipstream_conf.strict_errors = conf_parse_bool(value);
    return Conf_OK;
}
static ConfRes SET_max_errors(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    uint64_t n = 0;
    if (!conf_parse_int_checked(value, &n)) {
        LOG(LEVEL_ERROR, "max-errors: \"%s\" is not a non-negative integer. "
                         "Use an integer count, or 0 to disable the limit.\n",
            value ? value : "");
        return Conf_ERR;
    }
    ipstream_conf.max_errors = n;
    return Conf_OK;
}
static ConfRes SET_max_rate(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    uint64_t n = 0;
    if (!conf_parse_int_checked(value, &n)) {
        LOG(LEVEL_ERROR, "max-error-rate: \"%s\" is not an integer percent "
                         "(0..100).\n", value ? value : "");
        return Conf_ERR;
    }
    if (n > 100) {
        LOG(LEVEL_ERROR, "max-error-rate: %llu is out of range (0..100 "
                         "percent).\n", (unsigned long long)n);
        return Conf_ERR;
    }
    ipstream_conf.max_error_percent = (unsigned)n;
    return Conf_OK;
}

static ConfParam ipstream_parameters[] = {
    {"strict-errors", SET_strict, Type_FLAG, {"strict", 0},
     "Abort on the first invalid target line."},
    {"max-errors", SET_max_errors, Type_ARG, {"max-bad", 0},
     "Abort after this many invalid target lines (0 disables)."},
    {"max-error-rate", SET_max_rate, Type_ARG, {"max-bad-rate", 0},
     "Abort when invalid lines exceed this percent of lines read."},
    {"default-port",
     SET_port,
     Type_ARG,
     {"port", "p", 0},
     "Specifies target ports for the input stream has no port info. like -p "
     "80. "
     "UDP ports can be specified, like --ports U:161,u:1024-1100. SCTP ports "
     "can be specified like --ports S:36412,s:38412, too.\n"
     "NOTE: We also support `--ports O:16` to present non-port number in range"
     " [0..65535] for some ScanModules."},
    {"ip-file",
     SET_file,
     Type_ARG,
     {"file", "f", 0},
     "Specifies a file as input stream. Default is stdin."},
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

bool ipstream_init(const XConf *xconf, uint64_t *count_targets,
                   uint64_t *count_endpoints, bool *init_ipv4,
                   bool *init_ipv6) {
    if (xconf->tx_thread_count != 1) {
        LOG(LEVEL_ERROR, "(stream generator) supports only 1 tx thread.\n");
        return false;
    }

    if (ipstream_conf.targets.count_ports == 0) {
        LOG(LEVEL_HINT,
            "(stream generator) use o:0 as default port for no specified.\n");
        targetset_add_port_str(&ipstream_conf.targets, "o:0", 0);
        rangelist_optimize(&ipstream_conf.targets.ports);
        ipstream_conf.targets.count_ports =
            rangelist_count(&ipstream_conf.targets.ports);
    }

    if (!ipstream_conf.fp) {
        ipstream_conf.fp = stdin;
    }

    if (ipstream_conf.rounds <= 0) {
        ipstream_conf.rounds = XCONF_DFT_BLACKROCK_ROUNDS;
    }

    /*init all adapter in default*/
    *init_ipv4 = true;
    *init_ipv6 = true;

    ipstream_conf.seed = xconf->seed;

    return true;
}

bool ipstream_hasmore(unsigned tx_index, uint64_t index) {

    if (ipstream_conf.index < ipstream_conf.range_all)
        return true;

    /*remove old ips */
    TargetSet *cur_tgt = &ipstream_conf.targets;
    targetset_rm_ip(cur_tgt);

    /*add new ips*/
    char line[256];
    while (true) {
        bool too_long = false;
        int rr = stream_read_line(ipstream_conf.fp, line, sizeof(line),
                                  ipstream_conf.filename,
                                  &ipstream_conf.line_number,
                                  &ipstream_conf.bad_lines, &too_long);
        if (rr < 0) {
            if (ferror(ipstream_conf.fp))
                LOG(LEVEL_DEBUG, "(stream generator) error of stream.\n");
            else if (feof(ipstream_conf.fp)) {
                LOG(LEVEL_DEBUG, "(stream generator) EOF of stream.\n");
                if (ipstream_conf.valid_lines == 0 && ipstream_conf.bad_lines > 0) {
                    LOG(LEVEL_ERROR, "%s: no valid targets; all input lines were rejected\n",
                        ipstream_conf.filename ? ipstream_conf.filename : "<stdin>");
                    exit(1);
                }
            }
            return false;
        }

        if (rr > 0) {
            if (stream_bad_limit(ipstream_conf.bad_lines, ipstream_conf.line_number,
                            ipstream_conf.strict_errors, ipstream_conf.max_errors,
                            ipstream_conf.max_error_percent,
                            ipstream_conf.filename, ipstream_conf.line_number)) exit(1);
            LOG(LEVEL_ERROR, "%s:%llu: target line too long (max %zu bytes)\n",
                ipstream_conf.filename ? ipstream_conf.filename : "<stdin>",
                (unsigned long long)ipstream_conf.line_number,
                sizeof(line) - 1);
            continue;
        }

        char *s = line;
        /*absolute null line or the last line*/
        if (s[0] == '\n' || s[0] == '\r') {
            continue;
        }

        int err = targetset_add_ip_str(cur_tgt, line);
        if (err) {
            ipstream_conf.bad_lines++;
            if (stream_bad_limit(ipstream_conf.bad_lines, ipstream_conf.line_number,
                            ipstream_conf.strict_errors, ipstream_conf.max_errors,
                            ipstream_conf.max_error_percent,
                            ipstream_conf.filename, ipstream_conf.line_number)) exit(1);
            LOG(LEVEL_ERROR, "%s:%llu: invalid ip in address: %s",
                ipstream_conf.filename ? ipstream_conf.filename : "<stdin>",
                (unsigned long long)ipstream_conf.line_number, line);
            continue;
        }

        /*update relevant info*/
        rangelist_optimize(&cur_tgt->ipv4);
        range6list_optimize(&cur_tgt->ipv6);

        cur_tgt->count_ipv4s    = rangelist_count(&cur_tgt->ipv4);
        cur_tgt->count_ipv6s    = range6list_count(&cur_tgt->ipv6);
        cur_tgt->ipv4_threshold = cur_tgt->count_ipv4s * cur_tgt->count_ports;

        /**
         * !only support 63-bit scans for every line
         */
        if (int128_bitcount(targetset_count(cur_tgt)) > 63) {
            ipstream_conf.bad_lines++;
            if (stream_bad_limit(ipstream_conf.bad_lines, ipstream_conf.line_number,
                            ipstream_conf.strict_errors, ipstream_conf.max_errors,
                            ipstream_conf.max_error_percent,
                            ipstream_conf.filename, ipstream_conf.line_number)) exit(1);
            LOG(LEVEL_ERROR,
                "%s:%llu: (stream generator) range too large for scanning: "
                "%u-bits(>63).\n",
                ipstream_conf.filename ? ipstream_conf.filename : "<stdin>",
                (unsigned long long)ipstream_conf.line_number,
                int128_bitcount(targetset_count(cur_tgt)));
            targetset_rm_ip(cur_tgt);
            continue;
        }

        if (cur_tgt->count_ipv4s == 0 && cur_tgt->count_ipv6s.hi == 0 &&
            cur_tgt->count_ipv6s.lo == 0) {
            ipstream_conf.bad_lines++;
            if (stream_bad_limit(ipstream_conf.bad_lines, ipstream_conf.line_number,
                            ipstream_conf.strict_errors, ipstream_conf.max_errors,
                            ipstream_conf.max_error_percent,
                            ipstream_conf.filename, ipstream_conf.line_number)) exit(1);
            LOG(LEVEL_ERROR, "%s:%llu: no ip in address: %s",
                ipstream_conf.filename ? ipstream_conf.filename : "<stdin>",
                (unsigned long long)ipstream_conf.line_number, line);
            targetset_rm_ip(cur_tgt);
            continue;
        }
        ipstream_conf.valid_lines++;
        break;
    }

    if (cur_tgt->count_ipv6s.hi != 0 || cur_tgt->count_ports == 0) {
        LOG(LEVEL_ERROR, "(stream generator) target range too large or empty\n");
        return false;
    }
    uint64_t total_ips = cur_tgt->count_ipv4s + cur_tgt->count_ipv6s.lo;
    if (total_ips > UINT64_MAX / cur_tgt->count_ports) {
        LOG(LEVEL_ERROR, "(stream generator) target count overflow\n");
        return false;
    }
    ipstream_conf.range_all = total_ips * cur_tgt->count_ports;
    ipstream_conf.index = 0;

    /*init blackrock again*/
    if (!ipstream_conf.no_random)
        blackrock1_init(&ipstream_conf.br_table, ipstream_conf.range_all,
                        ipstream_conf.seed, ipstream_conf.rounds);

    return true;
}

Target ipstream_generate(unsigned tx_index, uint64_t index, uint64_t repeat,
                         struct source_t *src) {
    Target     target;
    TargetSet *cur_tgt = &ipstream_conf.targets;
    uint64_t   xXx     = ipstream_conf.index;
    uint64_t   ck;

    /*Actually it is impossible*/
    while (xXx >= ipstream_conf.range_all) {
        xXx -= ipstream_conf.range_all;
    }

    if (!ipstream_conf.no_random)
        xXx = blackrock1_shuffle(&ipstream_conf.br_table, xXx);

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
                (unsigned)xXx, (unsigned)(xXx >> 32), ipstream_conf.seed);
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
                (unsigned)xXx, (unsigned)(xXx >> 32), ipstream_conf.seed);
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

    ipstream_conf.index++;

    return target;
}

void ipstream_close() {
    if (ipstream_conf.fp != stdin) {
        fclose(ipstream_conf.fp);
    }
    ipstream_conf.fp = NULL;
    targetset_rm_all(&ipstream_conf.targets);
}

Generator IpStreamGen = {
    .name   = "ip-stream",
    .params = ipstream_parameters,
    .short_desc =
        "Generates targets by IP range list from stdin or file stream.",
    .desc = "IpStream module generates target from stdin or file stream. The "
            "stream contains IP range in lines without target ports. So we "
            "need specify a  port range for all targets or use 'o:0' as "
            "default. For every IP range(line), IpStream will do random "
            "picking with port by blackrock algorithm.\n"
            "NOTE: IpStream will block the tx thread while waiting the "
            "stream to be readable, this would break the rule of scan rate. "
            "However, the scan rate won't exceed the configured value.",

    .init_cb     = &ipstream_init,
    .hasmore_cb  = &ipstream_hasmore,
    .generate_cb = &ipstream_generate,
    .close_cb    = &ipstream_close,
};
