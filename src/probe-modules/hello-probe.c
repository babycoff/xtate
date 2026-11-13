#include "probe-modules.h"
#include "../util-data/file-open.h"

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

struct HelloConf {
    unsigned char *hello;
    size_t         hello_len;
#ifndef NOT_FOUND_PCRE2
    char                *regex;
    size_t               regex_len;
    pcre2_code          *compiled_re;
    pcre2_match_context *match_ctx;
    unsigned             re_case_insensitive : 1;
    unsigned             re_include_newlines : 1;
#endif
};

static struct HelloConf hello_conf = {0};

#ifndef NOT_FOUND_PCRE2

static ConfRes SET_newlines(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hello_conf.re_include_newlines = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_insensitive(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    hello_conf.re_case_insensitive = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_regex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (hello_conf.compiled_re)
        pcre2_code_free(hello_conf.compiled_re);
    if (hello_conf.match_ctx)
        pcre2_match_context_free(hello_conf.match_ctx);

    hello_conf.regex_len = strlen(value);
    if (hello_conf.regex_len == 0) {
        LOG(LEVEL_ERROR, "invalid regex.\n");
        return Conf_ERR;
    }

    int        pcre2_errcode;
    PCRE2_SIZE pcre2_erroffset;
    FREE(hello_conf.regex);
    hello_conf.regex = STRDUP(value);
    hello_conf.compiled_re =
        pcre2_compile((PCRE2_SPTR)hello_conf.regex, PCRE2_ZERO_TERMINATED,
                      (hello_conf.re_case_insensitive ? PCRE2_CASELESS : 0) |
                          (hello_conf.re_include_newlines ? PCRE2_DOTALL : 0),
                      &pcre2_errcode, &pcre2_erroffset, NULL);

    if (!hello_conf.compiled_re) {
        LOG(LEVEL_ERROR, "regex compiled failed.\n");
        FREE(hello_conf.regex);
        return Conf_ERR;
    }

    hello_conf.match_ctx = pcre2_match_context_create(NULL);
    if (!hello_conf.match_ctx) {
        LOG(LEVEL_ERROR, "regex allocates match_ctx failed.\n");
        FREE(hello_conf.regex);
        return Conf_ERR;
    }

    pcre2_set_match_limit(hello_conf.match_ctx, 100000);

#ifdef pcre2_set_depth_limit
    // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for function
    // names, so we don't have to add this to configure.ac.
    pcre2_set_depth_limit(hello_conf.match_ctx, 10000);
#else
    pcre2_set_recursion_limit(hello_conf.match_ctx, 10000);
#endif

    return Conf_OK;
}

#endif

static ConfRes SET_hello_string(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hello_conf.hello);

    hello_conf.hello_len = strlen(value);
    if (hello_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string.\n");
        return Conf_ERR;
    }
    hello_conf.hello = MALLOC(hello_conf.hello_len);
    memcpy(hello_conf.hello, value, hello_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_nmap(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hello_conf.hello);

    hello_conf.hello_len = strlen(value);
    if (hello_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in nmap probe format.\n");
        return Conf_ERR;
    }

    hello_conf.hello     = CALLOC(1, hello_conf.hello_len);
    hello_conf.hello_len = nmapprobe_decode(
        value, hello_conf.hello_len, hello_conf.hello, hello_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_base64(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hello_conf.hello);

    hello_conf.hello_len = strlen(value);
    if (hello_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in base64 format.\n");
        return Conf_ERR;
    }

    hello_conf.hello = CALLOC(1, hello_conf.hello_len);
    hello_conf.hello_len =
        base64_decode((char *)hello_conf.hello, hello_conf.hello_len, value,
                      hello_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(hello_conf.hello);

    FILE *fp = file_open_utf8_mode(value, "rb");
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

    hello_conf.hello_len = bytes_read;
    hello_conf.hello     = MALLOC(bytes_read);
    memcpy(hello_conf.hello, buf, bytes_read);

    return Conf_OK;
}

static ConfParam hello_parameters[] = {
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
#endif

    {0}};

/*for internal x-ref*/
extern Probe HelloProbe;

static bool hello_init(const XConf *xconf) {
    if (hello_conf.hello == NULL || hello_conf.hello_len == 0) {
        hello_conf.hello     = NULL;
        hello_conf.hello_len = 0;
        LOG(LEVEL_ERROR,
            "HelloProbe: No hello data specified, just wait response.\n");
    }

    return true;
}

static size_t hello_make_payload(ProbeTarget   *target,
                                 unsigned char *payload_buf) {
    if (hello_conf.hello == NULL || hello_conf.hello_len == 0) {
        return 0;
    }

    memcpy(payload_buf, hello_conf.hello, hello_conf.hello_len);
    return hello_conf.hello_len;
}

static size_t hello_get_payload_length(ProbeTarget *target) {
    return hello_conf.hello_len;
}

static unsigned hello_handle_response(unsigned th_idx, ProbeTarget *target,
                                      const unsigned char *px,
                                      unsigned sizeof_px, OutItem *item) {
#ifndef NOT_FOUND_PCRE2

    if (hello_conf.compiled_re) {
        pcre2_match_data *match_data;
        int               rc;

        match_data =
            pcre2_match_data_create_from_pattern(hello_conf.compiled_re, NULL);
        if (!match_data) {
            LOG(LEVEL_ERROR, "cannot allocate match_data when matching.\n");
            item->no_output = 1;
            return 0;
        }

        rc =
            pcre2_match(hello_conf.compiled_re, (PCRE2_SPTR8)px, (int)sizeof_px,
                        0, 0, match_data, hello_conf.match_ctx);

        /*matched one. ps: "offset is too small" means successful, too*/
        if (rc >= 0) {
            item->level = OUT_SUCCESS;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "matched");
        } else {
            item->level = OUT_FAILURE;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "not matched");
        }

        pcre2_match_data_free(match_data);
    } else {
#endif

        item->level = OUT_SUCCESS;

#ifndef NOT_FOUND_PCRE2
    }
#endif

    return 0;
}

static void hello_close() {
    FREE(hello_conf.hello);
    hello_conf.hello_len = 0;

#ifndef NOT_FOUND_PCRE2
    FREE(hello_conf.regex);
    hello_conf.regex_len = 0;

    if (hello_conf.compiled_re) {
        pcre2_code_free(hello_conf.compiled_re);
        hello_conf.compiled_re = NULL;
    }

    if (hello_conf.match_ctx) {
        pcre2_match_context_free(hello_conf.match_ctx);
        hello_conf.match_ctx = NULL;
    }
#endif
}

Probe HelloProbe = {
    .name       = "hello",
    .type       = ProbeType_TCP,
    .params     = hello_parameters,
    .short_desc =
        "Send user-specified payload and get response in stateless TCP scan.",
    .desc =
        "HelloProbe use static content set by user as hello data and reports "
        "banner. We can set hello data in different format and set a regex to "
        "match the response as successed. It is used to test POC immediatly.\n"
        "NOTE: If no hello data was specified, HelloProbe would just wait "
        "response.\n"
        "Dependencies: PCRE2 for regex.",

    .init_cb               = &hello_init,
    .make_payload_cb       = &hello_make_payload,
    .get_payload_length_cb = &hello_get_payload_length,
    .handle_response_cb    = &hello_handle_response,
    .close_cb              = &hello_close,
};