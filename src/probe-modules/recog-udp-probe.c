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

struct RecogUdpConf {
    unsigned char   *hello;
    size_t           hello_len;
    char            *xml_filename;
    struct Recog_FP *recog_fp;
    unsigned         unprefix : 1;
    unsigned         unsuffix : 1;
};

static struct RecogUdpConf recogudp_conf = {0};

static ConfRes SET_unsuffix(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogudp_conf.unsuffix = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_unprefix(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    recogudp_conf.unprefix = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_hello_string(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogudp_conf.hello);

    recogudp_conf.hello_len = strlen(value);
    if (recogudp_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string.\n");
        return Conf_ERR;
    }
    recogudp_conf.hello = MALLOC(recogudp_conf.hello_len);
    memcpy(recogudp_conf.hello, value, recogudp_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_nmap(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogudp_conf.hello);

    recogudp_conf.hello_len = strlen(value);
    if (recogudp_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in nmap probe format.\n");
        return Conf_ERR;
    }

    recogudp_conf.hello = CALLOC(1, recogudp_conf.hello_len);
    recogudp_conf.hello_len =
        nmapprobe_decode(value, recogudp_conf.hello_len, recogudp_conf.hello,
                         recogudp_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_base64(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogudp_conf.hello);

    recogudp_conf.hello_len = strlen(value);
    if (recogudp_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "invalid hello string in base64 format.\n");
        return Conf_ERR;
    }

    recogudp_conf.hello = CALLOC(1, recogudp_conf.hello_len);
    recogudp_conf.hello_len =
        base64_decode((char *)recogudp_conf.hello, recogudp_conf.hello_len,
                      value, recogudp_conf.hello_len);

    return Conf_OK;
}

static ConfRes SET_hello_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogudp_conf.hello);

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

    recogudp_conf.hello_len = bytes_read;
    recogudp_conf.hello     = MALLOC(bytes_read);
    memcpy(recogudp_conf.hello, buf, bytes_read);

    return Conf_OK;
}

static ConfRes SET_recog_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(recogudp_conf.xml_filename);

    recogudp_conf.xml_filename = STRDUP(value);

    return Conf_OK;
}

static ConfParam recogudp_parameters[] = {
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
extern Probe HelloUdpProbe;

static bool recogudp_init(const XConf *xconf) {
    if (recogudp_conf.hello == NULL || recogudp_conf.hello_len == 0) {
        LOG(LEVEL_ERROR, "(RecogUdpProbe) No hello data specified.\n");
        return false;
    }

    if (recogudp_conf.xml_filename == NULL ||
        recogudp_conf.xml_filename[0] == '\0') {
        LOG(LEVEL_ERROR,
            "RecogUdpProbe: No Recog fingerprint xml file specified.\n");
        return false;
    }

    recogudp_conf.recog_fp =
        load_recog_fp(recogudp_conf.xml_filename, recogudp_conf.unprefix,
                      recogudp_conf.unsuffix);
    if (recogudp_conf.recog_fp == NULL) {
        LOG(LEVEL_ERROR, "failed to load recog xml file %s.\n",
            recogudp_conf.xml_filename);
        return Conf_ERR;
    }

    return true;
}

static size_t recogudp_make_payload(ProbeTarget   *target,
                                    unsigned char *payload_buf) {
    if (recogudp_conf.hello == NULL || recogudp_conf.hello_len == 0) {
        return 0;
    }

    memcpy(payload_buf, recogudp_conf.hello, recogudp_conf.hello_len);
    return recogudp_conf.hello_len;
}

static bool recogudp_validate_response(ProbeTarget         *target,
                                       const unsigned char *px,
                                       unsigned             sizeof_px) {
    if (sizeof_px == 0) {
        return false;
    }

    /**
     * We leave the validation of recog to `handle_response`,
     * because we must report the matching result.
     */
    return true;
}

static unsigned recogudp_handle_response(unsigned th_idx, ProbeTarget *target,
                                         const unsigned char *px,
                                         unsigned sizeof_px, OutItem *item) {
    const char *match_res =
        match_recog_fp(recogudp_conf.recog_fp, px, sizeof_px);

    if (match_res) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "matched");
        dach_append(&item->probe_report, "result", match_res, strlen(match_res),
                    LinkType_String);
    } else {
        item->no_output = 1;
    }

    return 0;
}

static void recogudp_close() {
    FREE(recogudp_conf.hello);
    recogudp_conf.hello_len = 0;

    if (recogudp_conf.recog_fp) {
        free_recog_fp(recogudp_conf.recog_fp);
        recogudp_conf.recog_fp = NULL;
    }
}

Probe RecogUdpProbe = {
    .name       = "recog-udp",
    .type       = ProbeType_UDP,
    .params     = recogudp_parameters,
    .short_desc = "Try to match Recog fingerprints in UDP scan.",
    .desc =
        "RecogUdpProbe is the udp version of RecogProbe. RecogUdpProbe use "
        "static content set by user as hello data and match the response with "
        "specified Recog fingerprints. It's a proof of concept for service "
        "version detection.\n"
        "For RecogUdpProbe, it report all responses that matches fingerprints "
        "no matter where it came from. Consider how udp protocol works while "
        "using this probe.\n"
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

    .init_cb              = &recogudp_init,
    .make_payload_cb      = &recogudp_make_payload,
    .validate_response_cb = &recogudp_validate_response,
    .handle_response_cb   = &recogudp_handle_response,
    .close_cb             = &recogudp_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/