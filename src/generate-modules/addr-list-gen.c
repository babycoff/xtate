#include "generate-modules.h"

#include "../xconf.h"
#include "../util-data/file-open.h"
#include "stream-reader.h"
#include "../util-data/fine-malloc.h"
#include "../target/target-cookie.h"
#include "../target/target-parse.h"
#include "../target/target-rangeport.h"
#include "../target/target-rangev4.h"
#include "../util-data/safe-string.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

Generator AddrListGen;

struct AddrListConf {
    FILE     *fp;
    uint64_t  seed;
    ipaddress ip;
    unsigned  port;
    char      splitter[10];
    size_t    splitter_len;
    char     *filename;
    uint64_t  line_number;
    uint64_t  bad_lines;
    uint64_t  valid_lines;
    bool      strict_errors;
    uint64_t  max_errors;
    unsigned  max_error_percent;
};

static struct AddrListConf addrlist_conf = {0};

static ConfRes SET_splitter(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    safe_strcpy(addrlist_conf.splitter, sizeof(addrlist_conf.splitter), value);
    addrlist_conf.splitter_len = strlen(addrlist_conf.splitter);

    return Conf_OK;
}

static ConfRes SET_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (addrlist_conf.fp && addrlist_conf.fp != stdin) fclose(addrlist_conf.fp);
    FREE(addrlist_conf.filename);
    addrlist_conf.filename = STRDUP(value);
    addrlist_conf.fp = file_open_utf8(value);
    if (addrlist_conf.fp == NULL) {
        LOG(LEVEL_ERROR, "(list generator) %s: %s\n", value, strerror(errno));
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfRes SET_strict(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    addrlist_conf.strict_errors = conf_parse_bool(value);
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
    addrlist_conf.max_errors = n;
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
    addrlist_conf.max_error_percent = (unsigned)n;
    return Conf_OK;
}

static ConfParam addrlist_parameters[] = {
    {"strict-errors", SET_strict, Type_FLAG, {"strict", 0},
     "Abort on the first invalid target line."},
    {"max-errors", SET_max_errors, Type_ARG, {"max-bad", 0},
     "Abort after this many invalid target lines (0 disables)."},
    {"max-error-rate", SET_max_rate, Type_ARG, {"max-bad-rate", 0},
     "Abort when invalid lines exceed this percent of lines read."},
    {"address-file",
     SET_file,
     Type_ARG,
     {"addr-file", "file", "f", 0},
     "Specifies a file as input stream. Default is stdin."},
    {"splitter",
     SET_splitter,
     Type_ARG,
     {"split", 0},
     "Specifies a string as splitter of ip and port in input stream. "
     "Default splitter is a space."},

    {0}};

bool addrlist_init(const XConf *xconf, uint64_t *count_targets,
                   uint64_t *count_endpoints, bool *init_ipv4,
                   bool *init_ipv6) {
    if (xconf->tx_thread_count != 1) {
        LOG(LEVEL_ERROR, "(list generator) supports only 1 tx thread.\n");
        return false;
    }

    if (addrlist_conf.splitter[0] == '\0') {
        LOG(LEVEL_HINT,
            "(list generator) use space as splitter for no specified.\n");
        addrlist_conf.splitter[0]  = ' ';
        addrlist_conf.splitter_len = 1;
    }

    if (!addrlist_conf.fp) {
        addrlist_conf.fp = stdin;
    }

    /*init all adapter in default*/
    *init_ipv4 = true;
    *init_ipv6 = true;

    addrlist_conf.seed = xconf->seed;

    return true;
}

bool addrlist_hasmore(unsigned tx_index, uint64_t index) {

    if (addrlist_conf.ip.version != 0)
        return true;

    /*add new ips*/
    char line[256];
    while (true) {
        bool too_long = false;
        int rr = stream_read_line(addrlist_conf.fp, line, sizeof(line),
                                  addrlist_conf.filename,
                                  &addrlist_conf.line_number,
                                  &addrlist_conf.bad_lines, &too_long);
        if (rr < 0) {
            if (ferror(addrlist_conf.fp))
                LOG(LEVEL_ERROR, "%s: read error\n",
                    addrlist_conf.filename ? addrlist_conf.filename : "<stdin>");
            else {
                LOG(LEVEL_DEBUG, "(list generator) EOF of list.\n");
                if (addrlist_conf.valid_lines == 0 && addrlist_conf.bad_lines > 0) {
                    LOG(LEVEL_ERROR, "%s: no valid targets; all lines were rejected\n",
                        addrlist_conf.filename ? addrlist_conf.filename : "<stdin>");
                    exit(1);
                }
            }
            return false;
        }
        if (rr > 0) {
            if (stream_bad_limit(addrlist_conf.bad_lines, addrlist_conf.line_number,
                                 addrlist_conf.strict_errors, addrlist_conf.max_errors,
                                 addrlist_conf.max_error_percent,
                                 addrlist_conf.filename, addrlist_conf.line_number)) exit(1);
            LOG(LEVEL_ERROR, "%s:%llu: target line too long (max %zu bytes)\n",
                addrlist_conf.filename ? addrlist_conf.filename : "<stdin>",
                (unsigned long long)addrlist_conf.line_number, sizeof(line) - 1);
            continue;
        }
        char *s = line;
        /*absolute null line or the last line*/
        if (s[0] == '\n' || s[0] == '\r') {
            continue;
        }

        /*split ip range and port range*/
        char *sub = strstr(s, addrlist_conf.splitter);
        if (sub == NULL) {
            addrlist_conf.bad_lines++;
            if (stream_bad_limit(addrlist_conf.bad_lines, addrlist_conf.line_number,
                            addrlist_conf.strict_errors, addrlist_conf.max_errors,
                            addrlist_conf.max_error_percent,
                            addrlist_conf.filename, addrlist_conf.line_number)) exit(1);
            LOG(LEVEL_ERROR, "%s:%llu: invalid splitter in address: %s",
                addrlist_conf.filename ? addrlist_conf.filename : "<stdin>",
                (unsigned long long)addrlist_conf.line_number, line);
            continue;
        }

        sub[0]         = '\0';
        char *port_str = sub + addrlist_conf.splitter_len;

        addrlist_conf.ip = target_parse_ip(s);
        if (addrlist_conf.ip.version == 0) {
            addrlist_conf.bad_lines++;
            if (stream_bad_limit(addrlist_conf.bad_lines, addrlist_conf.line_number,
                            addrlist_conf.strict_errors, addrlist_conf.max_errors,
                            addrlist_conf.max_error_percent,
                            addrlist_conf.filename, addrlist_conf.line_number)) exit(1);
            sub[0] = addrlist_conf.splitter[0];
            LOG(LEVEL_ERROR, "%s:%llu: invalid ip in address: %s",
                addrlist_conf.filename ? addrlist_conf.filename : "<stdin>",
                (unsigned long long)addrlist_conf.line_number, line);
            continue;
        }

        unsigned         err   = 0;
        struct RangeList ports = {0};
        rangelist_parse_ports(&ports, port_str, &err, 0);
        if (err || ports.list_len != 1 ||
            ports.list[0].end != ports.list[0].begin) {
            rangelist_rm_all(&ports);
            addrlist_conf.bad_lines++;
            if (stream_bad_limit(addrlist_conf.bad_lines, addrlist_conf.line_number,
                            addrlist_conf.strict_errors, addrlist_conf.max_errors,
                            addrlist_conf.max_error_percent,
                            addrlist_conf.filename, addrlist_conf.line_number)) exit(1);
            sub[0] = addrlist_conf.splitter[0];
            LOG(LEVEL_ERROR, "%s:%llu: invalid port in address: %s",
                addrlist_conf.filename ? addrlist_conf.filename : "<stdin>",
                (unsigned long long)addrlist_conf.line_number, line);
            addrlist_conf.ip.version = 0;
            continue;
        }

        addrlist_conf.port = ports.list[0].begin;
        rangelist_rm_all(&ports);
        addrlist_conf.valid_lines++;

        break;
    }

    return true;
}

Target addrlist_generate(unsigned tx_index, uint64_t index, uint64_t repeat,
                         struct source_t *src) {
    Target   target;
    uint64_t ck;

    /**
     * Pick up target & source
     */
    target.ip_them   = addrlist_conf.ip;
    target.port_them = addrlist_conf.port;
    target.ip_proto  = get_actual_proto_port(&target.port_them);

    if (addrlist_conf.ip.version == 4) {
        target.ip_me.version = 4;

        if (src->ipv4_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)index, (unsigned)(index >> 32), addrlist_conf.seed);
            target.port_me    = src->port + (ck & src->port_mask);
            target.ip_me.ipv4 = src->ipv4 + ((ck >> 16) & src->ipv4_mask);
        } else {
            target.port_me    = src->port;
            target.ip_me.ipv4 = src->ipv4;
        }
    } else {
        target.ip_me.version = 6;
        target.ip_me.ipv6    = src->ipv6;

        if (src->ipv6_mask > 1 || src->port_mask > 1) {
            ck = get_cookie_ipv4(
                (unsigned)(index + repeat), (unsigned)((index + repeat) >> 32),
                (unsigned)index, (unsigned)(index >> 32), addrlist_conf.seed);
            target.port_me = src->port + (ck & src->port_mask);
            target.ip_me.ipv6.lo += (ck & src->ipv6_mask);
        } else {
            target.port_me = src->port;
        }
    }

    addrlist_conf.ip.version = 0;

    return target;
}

void addrlist_close() {
    if (addrlist_conf.fp != stdin) {
        fclose(addrlist_conf.fp);
    }
    addrlist_conf.fp = NULL;
}

Generator AddrListGen = {
    .name   = "addr-list",
    .params = addrlist_parameters,
    .short_desc =
        "Generates targets by IP/Port pairs from stdin or file stream.",
    .desc = "AddrList module generates target from stdin or file stream. The "
            "stream contains IP/Port pair in every line. Default splitter of "
            "ip and port is a space.\n"
            "NOTE: AddrList will block the tx thread while waiting the "
            "stream to be readable, this would break the rule of scan rate. "
            "However, the scan rate won't exceed the configured value.",

    .init_cb     = &addrlist_init,
    .hasmore_cb  = &addrlist_hasmore,
    .generate_cb = &addrlist_generate,
    .close_cb    = &addrlist_close,
};