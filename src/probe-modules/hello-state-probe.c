#include "probe-modules.h"
#include "../output-modules/output-modules.h"

#include <string.h>

#ifndef NOT_FOUND_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "../xconf.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"
#include "../crypto/crypto-base64.h"
#include "../crypto/crypto-nmapprobe.h"

struct HelloStateConf {
    unsigned char *hello;
    size_t         hello_len;
    unsigned       record_banner   : 1;
    unsigned       record_utf8     : 1;
    unsigned       record_data     : 1;
    unsigned       record_data_len : 1;
#ifndef NOT_FOUND_PCRE2
    char                *regex;
    size_t               regex_len;
    pcre2_code          *compiled_re;
    pcre2_match_context *match_ctx;
    unsigned             re_case_insensitive  : 1;
    unsigned             re_include_newlines  : 1;
    unsigned             match_whole_response : 1;
#endif
    unsigned all_banner : 1;
    unsigned all_banner_limit;
    unsigned all_banner_floor;
};

static struct HelloStateConf hellostate_conf = {0};

static ConfRes SET_all_banner_floor(void *conf, const char *name,
                                    const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.all_banner_floor = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_all_banner_limit(void *conf, const char *name,
                                    const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.all_banner_limit = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_all_banner(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.all_banner = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data_len(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.record_data_len = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.record_data = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_utf8(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.record_utf8 = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_banner(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.record_banner = conf_parse_bool(value);

    return Conf_OK;
}

#ifndef NOT_FOUND_PCRE2

static ConfRes SET_match_whole_response(void *conf, const char *name,
                                        const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.match_whole_response = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_newlines(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.re_include_newlines = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_insensitive(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hellostate_conf.re_case_insensitive = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_regex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hellostate_conf.compiled_re)
        pcre2_code_free(hellostate_conf.compiled_re);
    if (hellostate_conf.match_ctx)
        pcre2_match_context_free(hellostate_conf.match_ctx);

    hellostate_conf.regex_len = strlen(value);
    if (hellostate_conf.regex_len == 0) {
        LOG(LEVEL_ERROR, "invalid regex.\n");
        return Conf_ERR;
    }

    int        pcre2_errcode;
    PCRE2_SIZE pcre2_erroffset;
    FREE(hellostate_conf.regex);
    hellostate_conf.regex       = STRDUP(value);
    hellostate_conf.compiled_re = pcre2_compile(
        (PCRE2_SPTR)hellostate_conf.regex, PCRE2_ZERO_TERMINATED,
        (hellostate_conf.re_case_insensitive ? PCRE2_CASELESS : 0) |
            (hellostate_conf.re_include_newlines ? PCRE2_DOTALL : 0),
        &pcre2_errcode, &pcre2_erroffset, NULL);

    if (!hellostate_conf.compiled_re) {
        LOG(LEVEL_ERROR, "regex compiled failed.\n");
        FREE(hellostate_conf.regex);
        return Conf_ERR;
    }

    hellostate_conf.match_ctx = pcre2_match_context_create(NULL);
    if (!hellostate_conf.match_ctx) {
        LOG(LEVEL_ERROR, "regex allocates match_ctx failed.\n");
        FREE(hellostate_conf.regex);
        return Conf_ERR;
    }

    pcre2_set_match_limit(hellostate_conf.match_ctx, 100000);

#ifdef pcre2_set_depth_limit
    // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for function
    // names, so we don't have to add this to configure.ac.
    pcre2_set_depth_limit(hellostate_conf.match_ctx, 10000);
#else
    pcre2_set_recursion_limit(hellostate_conf.match_ctx, 10000);
#endif

    return Conf_OK;
}

#endif /*NOT_FOUND_PCRE2*/

static ConfRes SET_hello_string(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hellostate_conf.hello);

    hellostate_conf.hello_len = strlen(value);
    if (hellostate_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string.\n");
        return Conf_ERR;
    }
    hellostate_conf.hello = MALLOC(hellostate_conf.hello_len);
    memcpy(hellostate_conf.hello, value, hellostate_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_nmap(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hellostate_conf.hello);

    hellostate_conf.hello_len = strlen(value);
    if (hellostate_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in nmap probe format.\n");
        return Conf_ERR;
    }

    hellostate_conf.hello = CALLOC(1, hellostate_conf.hello_len);
    hellostate_conf.hello_len =
        nmapprobe_decode(value, hellostate_conf.hello_len,
                         hellostate_conf.hello, hellostate_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_base64(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hellostate_conf.hello);

    hellostate_conf.hello_len = strlen(value);
    if (hellostate_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in base64 format.\n");
        return Conf_ERR;
    }

    hellostate_conf.hello = CALLOC(1, hellostate_conf.hello_len);
    hellostate_conf.hello_len =
        base64_decode((char *)hellostate_conf.hello, hellostate_conf.hello_len,
                      value, hellostate_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hellostate_conf.hello);

    FILE *fp = fopen(value, "rb");
    if (fp == NULL) {
        LOG(LEVEL_ERROR, "failed to open file %s.\n", value);
        return Conf_ERR;
    }

    /**
     * We may specify a large size file accidently, so limit the size by a buf.
     */
    unsigned char buf[PM_PAYLOAD_SIZE];
    size_t        bytes_read = fread(buf, 1, PM_PAYLOAD_SIZE, fp);
    if (bytes_read == 0) {
        LOG(LEVEL_ERROR, "failed to read valid hello in file %s.\n", value);
        LOGPERROR(value);
        fclose(fp);
        return Conf_ERR;
    }
    fclose(fp);

    hellostate_conf.hello_len = bytes_read;
    hellostate_conf.hello     = MALLOC(bytes_read);
    memcpy(hellostate_conf.hello, buf, bytes_read);

    return Conf_OK;
}

static ConfParam hellostate_parameters[] = {
    {"string",
     SET_hello_string,
     Type_ARG,
     {0},
     "Specifies a string and set it as hello data after decoded."
     " This will overwrite hello data set by other parameters."},
    {"base64-string",
     SET_hello_base64,
     Type_ARG,
     {"base64", 0},
     "Specifies a string in base64 format and set it as hello data after "
     "decoded."
     " This will overwrite hello data set by other parameters."},
    {"nmap-string",
     SET_hello_nmap,
     Type_ARG,
     {"nmap", 0},
     "Specifies a string in nmap probe format and set it as hello data after "
     "decoded."
     " This will overwrite hello data set by other parameters."},
    {"file",
     SET_hello_file,
     Type_ARG,
     {0},
     "Specifies a file and set the content of file as hello data."
     " This will overwrite hello data set by other parameters."},
    {"record-banner",
     SET_record_banner,
     Type_FLAG,
     {"banner", 0},
     "Records banner content in escaped text style."},
    {"record-utf8",
     SET_record_utf8,
     Type_FLAG,
     {"utf8", 0},
     "Records banner content with escaped valid utf8 encoding."},
    {"record-data",
     SET_record_data,
     Type_FLAG,
     {"data", 0},
     "Records data content in binary format."},
    {"record-data-len",
     SET_record_data_len,
     Type_FLAG,
     {"data-len", "len", 0},
     "Records payload data length."},

#ifndef NOT_FOUND_PCRE2
    {"regex",
     SET_regex,
     Type_ARG,
     {0},
     "Specifies a regex and sets matched response data as successed instead of"
     " reporting all results."},
    {"case-insensitive",
     SET_insensitive,
     Type_FLAG,
     {"insensitive", 0},
     "Whether the specified regex is case-insensitive or not."},
    {"include-newlines",
     SET_newlines,
     Type_FLAG,
     {"include-newline", "newline", "newlines", 0},
     "Whether the specified regex contains newlines."},
    {"match-whole-response",
     SET_match_whole_response,
     Type_FLAG,
     {"match-whole", "whole-match", 0},
     "Continue to match the whole response after matched previous content "
     "instead of trying to close the connection.\n"
     "NOTE: it works while using --get-whole-response."},
#endif

    {"all-banner",
     SET_all_banner,
     Type_FLAG,
     {"banner-all", 0},
     "Get the whole responsed banner before connection timeout, not just the "
     "banner in the first segment."},
    {"all-banner-limit",
     SET_all_banner_limit,
     Type_ARG,
     {"banner-limit", "limit-banner", 0},
     "Just record limited number of ACK segments with banner data as results "
     "in all-banner mode. Exceeded ACK segments with banner data won't trigger "
     "slot expansion."},
    {"banner-floor",
     SET_all_banner_floor,
     Type_ARG,
     {"banner-floor", "floor-banner", 0},
     "Do not record ACK segments with banner data as results if the number is "
     "less than the floor value while in all-banner mode. And non-recorded "
     "segments won't trigger slot expansion."},

    {0}};

/*for internal x-ref*/
extern Probe HelloStateProbe;

static bool hellostate_init(const XConf *xconf) {
    if (hellostate_conf.hello == NULL || hellostate_conf.hello_len == 0) {
        hellostate_conf.hello     = NULL;
        hellostate_conf.hello_len = 0;
        LOG(LEVEL_ERROR,
            "HelloStateProbe: No hello data specified, just wait response.\n");
    }

    return true;
}

static void hellostate_make_hello(DataPass *pass, ProbeState *state,
                                  ProbeTarget *target) {
    datapass_set_data(pass, hellostate_conf.hello, hellostate_conf.hello_len,
                      false);
}

static unsigned hellostate_parse_response(DataPass *pass, ProbeState *state,
                                          OutConf *out, ProbeTarget *target,
                                          const unsigned char *px,
                                          unsigned             sizeof_px) {
    state->state++;

    if (!hellostate_conf.all_banner) {
        pass->is_close = 1;

        if (state->state > 1)
            return 0;
    }

    if (hellostate_conf.all_banner && hellostate_conf.all_banner_limit &&
        state->state >= hellostate_conf.all_banner_limit) {
        pass->is_close = 1;

        if (state->state > hellostate_conf.all_banner_limit)
            return 0;
        if (state->state < hellostate_conf.all_banner_floor)
            return 0;
    }

    if (hellostate_conf.all_banner && hellostate_conf.all_banner_floor &&
        state->state < hellostate_conf.all_banner_floor) {
        return 0;
    }

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };

#ifndef NOT_FOUND_PCRE2

    if (hellostate_conf.compiled_re) {
        pcre2_match_data *match_data;
        int               rc;

        match_data = pcre2_match_data_create_from_pattern(
            hellostate_conf.compiled_re, NULL);
        if (!match_data) {
            LOG(LEVEL_ERROR, "cannot allocate match_data when matching.\n");
            return 0;
        }

        rc = pcre2_match(hellostate_conf.compiled_re, (PCRE2_SPTR8)px,
                         (int)sizeof_px, 0, 0, match_data,
                         hellostate_conf.match_ctx);

        /*matched one. ps: "offset is too small" means successful, too*/
        if (rc >= 0) {
            item.level = OUT_SUCCESS;
            safe_strcpy(item.classification, OUT_CLS_SIZE, "matched");

            if (!hellostate_conf.match_whole_response) {
                pass->is_close = 1;
            }
        } else {
            item.level = OUT_FAILURE;
            safe_strcpy(item.classification, OUT_CLS_SIZE, "not matched");
        }

        pcre2_match_data_free(match_data);
    } else {
#endif

        item.level = OUT_SUCCESS;

#ifndef NOT_FOUND_PCRE2
    }
#endif

    if (hellostate_conf.all_banner) {
        dach_set_int(&item.probe_report, "banner idx", state->state - 1);
    }
    if (hellostate_conf.record_data_len) {
        dach_set_int(&item.probe_report, "data len", sizeof_px);
    }
    if (hellostate_conf.record_data)
        dach_append_bin(&item.probe_report, "data", px, sizeof_px);
    if (hellostate_conf.record_utf8)
        dach_append_utf8(&item.probe_report, "utf8", px, sizeof_px);
    if (hellostate_conf.record_banner)
        dach_append_banner(&item.probe_report, "banner", px, sizeof_px);

    output_result(out, &item);

    return 0;
}

static void hellostate_close() {
    FREE(hellostate_conf.hello);
    hellostate_conf.hello_len = 0;

#ifndef NOT_FOUND_PCRE2
    FREE(hellostate_conf.regex);
    hellostate_conf.regex_len = 0;

    if (hellostate_conf.compiled_re) {
        pcre2_code_free(hellostate_conf.compiled_re);
        hellostate_conf.compiled_re = NULL;
    }

    if (hellostate_conf.match_ctx) {
        pcre2_match_context_free(hellostate_conf.match_ctx);
        hellostate_conf.match_ctx = NULL;
    }
#endif
}

Probe HelloStateProbe = {
    .name       = "hello-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .params     = hellostate_parameters,
    .short_desc =
        "Send user-specified payload and get response in stateful TCP scan.",
    .desc =
        "HelloStateProbe is the stateful version of HelloPorbe, it uses static"
        " content set by user as hello data and reports banner. It is used to "
        "test POC immediatly under stateful TCP connection and can work with "
        "services over TLS. We can set hello data in different format and set"
        " a regex to match the the first response(banner) or whole response "
        " as successed.\n"
        "NOTE: If no hello data was specified, HelloStateProbe would just wait "
        "banner (first packet with response).\n"
        "Dependencies: PCRE2 for regex.",

    .init_cb           = &hellostate_init,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &hellostate_make_hello,
    .parse_response_cb = &hellostate_parse_response,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &hellostate_close,
};