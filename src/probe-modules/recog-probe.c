#ifndef NOT_FOUND_PCRE2

#include "probe-modules.h"

#include <string.h>

#include "../xconf.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"
#include "../crypto/crypto-base64.h"
#include "../crypto/crypto-nmapprobe.h"
#include "../recog/recog-fingerprint.h"

struct RecogConf {
    unsigned char   *hello;
    size_t           hello_len;
    char            *xml_filename;
    struct Recog_FP *recog_fp;
    unsigned         unprefix : 1;
    unsigned         unsuffix : 1;
};

static struct RecogConf recog_conf = {0};

static ConfRes SET_unsuffix(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recog_conf.unsuffix = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_unprefix(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recog_conf.unprefix = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_hello_string(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recog_conf.hello);

    recog_conf.hello_len = strlen(value);
    if (recog_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string.\n");
        return Conf_ERR;
    }
    recog_conf.hello = MALLOC(recog_conf.hello_len);
    memcpy(recog_conf.hello, value, recog_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_nmap(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recog_conf.hello);

    recog_conf.hello_len = strlen(value);
    if (recog_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in nmap probe format.\n");
        return Conf_ERR;
    }

    recog_conf.hello     = CALLOC(1, recog_conf.hello_len);
    recog_conf.hello_len = nmapprobe_decode(
        value, recog_conf.hello_len, recog_conf.hello, recog_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_base64(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recog_conf.hello);

    recog_conf.hello_len = strlen(value);
    if (recog_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in base64 format.\n");
        return Conf_ERR;
    }

    recog_conf.hello = CALLOC(1, recog_conf.hello_len);
    recog_conf.hello_len =
        base64_decode((char *)recog_conf.hello, recog_conf.hello_len, value,
                      recog_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recog_conf.hello);

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

    recog_conf.hello_len = bytes_read;
    recog_conf.hello     = MALLOC(bytes_read);
    memcpy(recog_conf.hello, buf, bytes_read);

    return Conf_OK;
}

static ConfRes SET_recog_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recog_conf.xml_filename);

    recog_conf.xml_filename = STRDUP(value);

    return Conf_OK;
}

static ConfParam recog_parameters[] = {
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
    {"recog-xml",
     SET_recog_file,
     Type_ARG,
     {"xml", "xml-file", 0},
     "Specifies a xml file in Recog fingerprint format as the matching "
     "source."},
    {"unprefix",
     SET_unprefix,
     Type_FLAG,
     {0},
     "Unprefix the '^' from the head of all regex. It's useful if we cannot "
     "extract exactly the proper part of string for matching."},
    {"unsuffix",
     SET_unsuffix,
     Type_FLAG,
     {0},
     "Unprefix the '$' from the tail of all regex. It's useful if we cannot "
     "extract exactly the proper part of string for matching."},

    {0}};

/*for internal x-ref*/
extern Probe RecogProbe;

static bool recog_init(const XConf *xconf) {
    if (recog_conf.hello == NULL || recog_conf.hello_len == 0) {
        recog_conf.hello     = NULL;
        recog_conf.hello_len = 0;
        LOG(LEVEL_ERROR,
            "RecogProbe: No hello data specified, just wait response.\n");
    }

    if (recog_conf.xml_filename == NULL || recog_conf.xml_filename[0] == '\0') {
        LOG(LEVEL_ERROR,
            "RecogProbe: No Recog fingerprint xml file specified.\n");
        return false;
    }

    recog_conf.recog_fp = load_recog_fp(
        recog_conf.xml_filename, recog_conf.unprefix, recog_conf.unsuffix);
    if (recog_conf.recog_fp == NULL) {
        LOG(LEVEL_ERROR, "failed to load recog xml file %s.\n",
            recog_conf.xml_filename);
        return Conf_ERR;
    }

    return true;
}

static size_t recog_make_payload(ProbeTarget   *target,
                                 unsigned char *payload_buf) {
    if (recog_conf.hello == NULL || recog_conf.hello_len == 0) {
        return 0;
    }

    memcpy(payload_buf, recog_conf.hello, recog_conf.hello_len);
    return recog_conf.hello_len;
}

static size_t recog_get_payload_length(ProbeTarget *target) {
    return recog_conf.hello_len;
}

static unsigned recog_handle_response(unsigned th_idx, ProbeTarget *target,
                                      const unsigned char *px,
                                      unsigned sizeof_px, OutItem *item) {
    const char *match_res = match_recog_fp(recog_conf.recog_fp, px, sizeof_px);

    if (match_res) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "matched");
        dach_append(&item->probe_report, "result", match_res, strlen(match_res),
                    LinkType_String);
    } else {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not matched");
    }

    return 0;
}

static void recog_close() {
    FREE(recog_conf.hello);
    recog_conf.hello_len = 0;

    if (recog_conf.recog_fp) {
        free_recog_fp(recog_conf.recog_fp);
        recog_conf.recog_fp = NULL;
    }
}

Probe RecogProbe = {
    .name       = "recog",
    .type       = ProbeType_TCP,
    .params     = recog_parameters,
    .short_desc = "Try to match Recog fingerprints in stateless TCP scan.",
    .desc =
        "RecogProbe use static content set by user as hello data and match the "
        "response with specified Recog fingerprints. It's a proof of concept "
        "for service version detection.\n"
        "NOTE1: Recog fingerprints are adapted for specific part of response "
        "data like html title, http cookie and etc. But RecogProbe doesn't "
        "prepare specific type of probes so that it cannot extract some part "
        "of data. However, we could ignore position parameters of regex like "
        "'^' and '$' by probe params to match the whole response. This is "
        "enough and useful to solve most cases. Implement your own probes if "
        "you want a more accurate results.\n"
        "NOTE2: I found the order of fingerprints in recog xml file would "
        "affect the identidying result because our probe just output the first "
        "matched result.\n"
        "Dependencies: PCRE2, LibXml2.",

    .init_cb               = &recog_init,
    .make_payload_cb       = &recog_make_payload,
    .get_payload_length_cb = &recog_get_payload_length,
    .handle_response_cb    = &recog_handle_response,
    .close_cb              = &recog_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/