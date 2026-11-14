#include "probe-modules.h"

#include <string.h>
#include <time.h>

#ifndef NOT_FOUND_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "../xconf.h"
#include "../util-data/safe-string.h"
#include "../util-data/data-convert.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

/*for internal x-ref*/
extern Probe TlsHelloProbe;

/**
 * A version-universal TLS clienthello extracted from configured OpenSSL and
 * supports TLS version from 1.0 to 1.3. It can test if the server supports
 * TLSv1.3. But we can get nothing useful from the encrypted domains and certs
 * from the TLSv1.3 ServerHello.
 * */
static char tls1_3_hello_payload[] =
    "\x16"                             /*handshake*/
    "\x03\x01"                         /*outter version TLSv1.0*/
    "\x01\xa6"                         /*record length 422*/
    "\x01"                             /*handshake*/
    "\x00\x01\xa2"                     /*handshake length 418*/
    "\x03\x03"                         /*inner version TLSv1.2*/
    "\x63\xb1\x56\x20\x58\x54\x1e\x06" /*random value*/
    "\x51\xcf\x01\x4f\x96\x87\x3b\xf7" /*random value*/
    "\x32\x42\x49\x78\xf5\x12\x0c\x05" /*random value*/
    "\xc9\x6b\x5f\x27\xe1\x7d\x2f\xef" /*random value*/
    "\x20"                             /*session id length 32*/
    "\x0d\x2b\x79\xe0\x81\xc5\x5c\x48" /*session id in random*/
    "\xd2\xd2\xc1\x7d\x1d\xc0\xaa\x8d" /*session id in random*/
    "\xc1\x58\xc3\xed\x99\x5f\x4d\x43" /*session id in random*/
    "\x7f\x35\x99\xf4\x3f\x3f\x61\x0b" /*session id in random*/
    "\x00\xba"                         /*cipher suites length 186*/
    /*93 cipher suites*/
    "\x13\x02\x13\x03\x13\x01\xc0\x2c\xc0\x30\x00\xa3\x00\x9f\xcc\xa9\xcc\xa8"
    "\xcc\xaa\xc0\xaf\xc0\xad\xc0\xa3\xc0\x9f\xc0\x5d\xc0\x61\xc0\x57"
    "\xc0\x53\x00\xa7\xc0\x2b\xc0\x2f\x00\xa2\x00\x9e\xc0\xae\xc0\xac"
    "\xc0\xa2\xc0\x9e\xc0\x5c\xc0\x60\xc0\x56\xc0\x52\x00\xa6\xc0\x24"
    "\xc0\x28\x00\x6b\x00\x6a\xc0\x73\xc0\x77\x00\xc4\x00\xc3\x00\x6d"
    "\x00\xc5\xc0\x23\xc0\x27\x00\x67\x00\x40\xc0\x72\xc0\x76\x00\xbe"
    "\x00\xbd\x00\x6c\x00\xbf\xc0\x0a\xc0\x14\x00\x39\x00\x38\x00\x88"
    "\x00\x87\xc0\x19\x00\x3a\x00\x89\xc0\x09\xc0\x13\x00\x33\x00\x32"
    "\x00\x45\x00\x44\xc0\x18\x00\x34\x00\x46\x00\x9d\xc0\xa1\xc0\x9d"
    "\xc0\x51\x00\x9c\xc0\xa0\xc0\x9c\xc0\x50\x00\x3d\x00\xc0\x00\x3c"
    "\x00\xba\x00\x35\x00\x84\x00\x2f\x00\x41\xc0\x06\xc0\x10\xc0\x15"
    "\x00\x3b\x00\x02\x00\x01\x00\xff"
    "\x01"                             /*compression method length 1*/
    "\x00"                             /*compression method: null */
    "\x00\x9f"                         /*extension length 159*/
    "\x00\x0b\x00\x04\x03\x00\x01\x02" /*ext ec_point_formats*/
    /*ext supported_groups*/
    "\x00\x0a\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e"
    "\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04"
    "\x00\x23\x00\x00" /*ext session_ticket (len=0)*/
    "\x00\x16\x00\x00" /*ext encrypt_then_mac (len=0)*/
    "\x00\x17\x00\x00" /*ext extended_master_secret (len=0)*/
    /*ext signature_algorithms*/
    "\x00\x0d\x00\x30\x00\x2e"
    "\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b"
    "\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x02\x03"
    "\x03\x01\x02\x01\x03\x02\x02\x02\x04\x02\x05\x02\x06\x02"
    /*ext supported_versions*/
    "\x00\x2b"
    "\x00\x09\x08"
    "\x03\x04"                 /*TLSv1.3*/
    "\x03\x03"                 /*TLSv1.2*/
    "\x03\x02"                 /*TLSv1.1*/
    "\x03\x01"                 /*TLSv1.0*/
    "\x00\x2d\x00\x02\x01\x01" /*ext psk_key_exchange_modes*/
    /*ext key_share*/
    "\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x75\xa9\x2c\x5e\x01"
    "\x6a\xd0\xe6\x90\x02\x7e\xc3\x8b\x64\x48\x9b\xd2\xc6\xcb\x02\xe7"
    "\x90\xec\x76\x80\x91\xc6\x95\xc4\x2c\x1b\x26";

/**
 * A fixed TLS ClientHello that supports TLS version from 1.0
 * to 1.2. It can get domain and cert info from the response ServerHello but cannot
 * test if the server supports TLSv1.3. This is the default payload of
 * TlsHelloProbe.
 * */
static char tls1_2_hello_payload[] =
    "\x16"                                 /*handshake*/
    "\x03\x01"                             /*TLSv1.0*/
    "\x00\x75"                             /*length 117*/
    "\x01"                                 /*client hello*/
    "\x00\x00\x71"                         /*length 113*/
    "\x03\x03"                             /*TLSv1.2*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00\x00\x00\x00\x00\x00\x00\x00"     /*random*/
    "\x00"                                 /*session ID length 0*/
    "\x00\x1a"                             /*cipher suites lenght 26*/
    "\xc0\x2f"                             /*cipher suite*/
    "\xc0\x2b"                             /*cipher suite*/
    "\xc0\x11"                             /*cipher suite*/
    "\xc0\x07"                             /*cipher suite*/
    "\xc0\x13"                             /*cipher suite*/
    "\xc0\x09"                             /*cipher suite*/
    "\xc0\x14"                             /*cipher suite*/
    "\xc0\x0a"                             /*cipher suite*/
    "\x00\x05"                             /*cipher suite*/
    "\x00\x2f"                             /*cipher suite*/
    "\x00\x35"                             /*cipher suite*/
    "\xc0\x12"                             /*cipher suite*/
    "\x00\x0a"                             /*cipher suite*/
    "\x01"                                 /*compression methods length*/
    "\x00"                                 /*compression methods*/
    "\x00\x2e"                             /*extension length 46*/
    "\x00\x05\x00\x05\x01\x00\x00\x00\x00" /*ext status request*/
    "\x00\x0a\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19" /*ext supported
                                                          groups*/
    "\x00\x0b\x00\x02\x01\x00"                         /*ext ec point formats*/
    "\x00\x0d\x00\x0a\x00\x08\x04\x01\x04\x03\x02\x01\x02\x03" /*ext
                                                                  signature
                                                                  algorithms*/
    "\xff\x01\x00\x01\x00" /*ext renegotiation info*/
    ;

struct TlsHello {
    char    *tls_hello_payload;
    unsigned tls_hello_payload_len;
    unsigned support_tls1_3 : 1;
#ifndef NOT_FOUND_PCRE2
    char                *regex;
    size_t               regex_len;
    pcre2_code          *compiled_re;
    pcre2_match_context *match_ctx;
    unsigned             re_case_insensitive : 1;
    unsigned             re_include_newlines : 1;
#endif
};

static struct TlsHello tlshello_conf = {0};

static ConfRes SET_support_tls1_3(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlshello_conf.support_tls1_3 = conf_parse_bool(value);

    return Conf_OK;
}

#ifndef NOT_FOUND_PCRE2

static ConfRes SET_newlines(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlshello_conf.re_include_newlines = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_insensitive(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlshello_conf.re_case_insensitive = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_regex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    if (tlshello_conf.compiled_re)
        pcre2_code_free(tlshello_conf.compiled_re);
    if (tlshello_conf.match_ctx)
        pcre2_match_context_free(tlshello_conf.match_ctx);

    tlshello_conf.regex_len = strlen(value);
    if (tlshello_conf.regex_len == 0) {
        LOG(LEVEL_ERROR, "invalid regex.\n");
        return Conf_ERR;
    }

    int        pcre2_errcode;
    PCRE2_SIZE pcre2_erroffset;
    FREE(tlshello_conf.regex);
    tlshello_conf.regex       = STRDUP(value);
    tlshello_conf.compiled_re = pcre2_compile(
        (PCRE2_SPTR)tlshello_conf.regex, PCRE2_ZERO_TERMINATED,
        (tlshello_conf.re_case_insensitive ? PCRE2_CASELESS : 0) |
            (tlshello_conf.re_include_newlines ? PCRE2_DOTALL : 0),
        &pcre2_errcode, &pcre2_erroffset, NULL);

    if (!tlshello_conf.compiled_re) {
        LOG(LEVEL_ERROR, "regex compiled failed.\n");
        FREE(tlshello_conf.regex);
        return Conf_ERR;
    }

    tlshello_conf.match_ctx = pcre2_match_context_create(NULL);
    if (!tlshello_conf.match_ctx) {
        LOG(LEVEL_ERROR, "regex allocates match_ctx failed.\n");
        FREE(tlshello_conf.regex);
        return Conf_ERR;
    }

    pcre2_set_match_limit(tlshello_conf.match_ctx, 100000);

#ifdef pcre2_set_depth_limit
    // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for function
    // names, so we don't have to add this to configure.ac.
    pcre2_set_depth_limit(tlshello_conf.match_ctx, 10000);
#else
    pcre2_set_recursion_limit(tlshello_conf.match_ctx, 10000);
#endif

    return Conf_OK;
}

#endif

static ConfParam tlshello_parameters[] = {
    {"support-tls13",
     SET_support_tls1_3,
     Type_FLAG,
     {"tls13", 0},
     "Use probe payload which supports TLSv1.3. The default payload of "
     "TlsHelloProbe supports TLS version from 1.0 to 1.2 and can match regex "
     "from cert and domain of response. But it cannot test if the server "
     "supports TLSv1.3. However, if we use payload which supports TLSv1.3, we "
     "could just get encrypted cert and domain info from the response "
     "ServerHello.\n"
     "NOTE: I suggest using default payload as probe if we don't care if the "
     "server supports TLSv1.3. However, most of the servers which support "
     "TLSv1.3 will also support TLSv1.2 so that we can get more info from the "
     "response banner."},

#ifndef NOT_FOUND_PCRE2
    {"regex",
     SET_regex,
     Type_ARG,
     {0},
     "Specifies a regex and marks matched response data as success instead of"
     " reporting all results matched in protocol.\n"
     "NOTE1: TlsHello only match the regex while it gets a ServerHello in type "
     "of HANDSHAKE. We just want to match regex with cert and domain info but "
     "ALERT ServerHello has none of them.\n"
     "NOTE2: TlsHello won't match the regex if the server responses in "
     "TLSv1.3. Because the cert and domain info is encrypted in TLSv1.3."},
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

static bool tlshello_init(const XConf *xconf) {
    if (tlshello_conf.support_tls1_3) {
        tlshello_conf.tls_hello_payload     = tls1_3_hello_payload;
        tlshello_conf.tls_hello_payload_len = sizeof(tls1_3_hello_payload) - 1;
    } else {
        tlshello_conf.tls_hello_payload     = tls1_2_hello_payload;
        tlshello_conf.tls_hello_payload_len = sizeof(tls1_2_hello_payload) - 1;
    }

    /*fill the random bytes in payload*/
    unsigned r;
    srand((unsigned)time(NULL));
    /*random the Random*/
    char *p = tlshello_conf.tls_hello_payload + 11;
    for (unsigned i = 0; i < 32 / 4; i++) {
        r = rand();
        U32_TO_BE((unsigned char *)p, r);
        p += 4;
    }

    if (tlshello_conf.support_tls1_3) {
        /*random the session id*/
        p = tlshello_conf.tls_hello_payload + 44;
        for (unsigned i = 0; i < 32 / 4; i++) {
            r = rand();
            U32_TO_BE((unsigned char *)p, r);
            p += 4;
        }
    }

    return true;
}

static size_t tlshello_make_payload(ProbeTarget   *target,
                                    unsigned char *payload_buf) {
    memcpy(payload_buf, tlshello_conf.tls_hello_payload,
           tlshello_conf.tls_hello_payload_len);
    return tlshello_conf.tls_hello_payload_len;
}

static size_t tlshello_get_payload_length(ProbeTarget *target) {
    return tlshello_conf.tls_hello_payload_len;
}

static unsigned tlshello_handle_reponse(unsigned th_idx, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned sizeof_px, OutItem *item) {

    if (sizeof_px < 3) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");
        /*no further info*/
        return 0;
    }

    if (safe_memmem(px, sizeof_px, "HTTPS", strlen("HTTPS"))) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "maybe TLS");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol matched https");
        /*no further info*/
        return 0;
    }

    /**
     * NOTE: We should only recv HANDSHAKE or ALERT
     */
    // http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
    //  Record Type Values       dec      hex
    //  -------------------------------------
    //  CHANGE_CIPHER_SPEC        20     0x14
    //  ALERT                     21     0x15
    //  HANDSHAKE                 22     0x16
    //  APPLICATION_DATA          23     0x17
    // Version Values            dec     hex
    //  -------------------------------------
    //  SSL 3.0                   3,0  0x0300
    //  TLS 1.0                   3,1  0x0301
    //  TLS 1.1                   3,2  0x0302
    //  TLS 1.2                   3,3  0x0303
    //  TLS 1.3                   3,4  0x0304

    /*HANDSHAKE: we identify TLS version by field in Handshake Protocol*/
    if (px[0] == 0x16 && px[1] == 0x03 && px[2] >= 0x00 && px[2] <= 0x04 &&
        sizeof_px >= 11 && px[9] == 0x03) {
        if (px[10] == 0x00) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "SSLv3.0");
        } else if (px[10] == 0x01) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.0");
        } else if (px[10] == 0x02) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.1");
        } else if (px[10] == 0x03) {
            /*if we use payload which supports TLSv1.3, we could know if the
             * server supports TLSv1.3. */
            if (tlshello_conf.support_tls1_3) {
                /**
                 * Just test if the ServerHello has Extension of
                 * supported_versions with TLSv1.3:
                 * "\x00\x2b"  type: supported_versions
                 * "\x00\x02"  length: 2
                 * "\x03\x04"  version: TLSv1.3
                 */
                if (safe_memmem(px, sizeof_px, "\x00\x2b\x00\x02\x03\x04",
                                sizeof("\x00\x2b\x00\x02\x03\x04") - 1)) {
                    safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.3");
#ifndef NOT_FOUND_PCRE2
                    if (tlshello_conf.compiled_re) {
                        item->level = OUT_FAILURE;
                        safe_strcpy(item->reason, OUT_RSN_SIZE,
                                    "regex not matched in TLSv1.3");
                    } else {
#endif
                        item->level = OUT_SUCCESS;
                        safe_strcpy(item->reason, OUT_RSN_SIZE,
                                    "protocol matched");
#ifndef NOT_FOUND_PCRE2
                    }
#endif
                    dach_append_str(&item->probe_report, "type", "handshake",
                                    sizeof("handshake") - 1);
                    return 0;
                }
            }

            /*we can go on to regex matching if the version is under TLSv1.3*/
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.2");
        } else {
            item->level = OUT_FAILURE;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");
            /*no further info*/
            return 0;
        }

        item->level = OUT_SUCCESS;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol matched");
        dach_append_str(&item->probe_report, "type", "handshake",
                        sizeof("handshake") - 1);

        /*we can do further regex matching here*/
#ifndef NOT_FOUND_PCRE2

        if (tlshello_conf.compiled_re) {
            pcre2_match_data *match_data;
            int               rc;

            match_data = pcre2_match_data_create_from_pattern(
                tlshello_conf.compiled_re, NULL);
            if (!match_data) {
                LOG(LEVEL_ERROR, "cannot allocate match_data when matching.\n");
                item->no_output = 1;
                return 0;
            }

            rc = pcre2_match(tlshello_conf.compiled_re, (PCRE2_SPTR8)px,
                             (int)sizeof_px, 0, 0, match_data,
                             tlshello_conf.match_ctx);

            /*matched one. ps: "offset is too small" means successful, too*/
            if (rc >= 0) {
                item->level = OUT_SUCCESS;
                safe_strcpy(item->reason, OUT_RSN_SIZE, "regex matched");
            } else {
                item->level = OUT_FAILURE;
                safe_strcpy(item->reason, OUT_RSN_SIZE, "regex not matched");
            }

            pcre2_match_data_free(match_data);
        }
#endif

        return 0;

    } else if (px[0] == 0x15 && px[1] == 0x03 && sizeof_px >= 7) {
        /* TLS Alert record: type(1) version(2) length(2) level(1) desc(1).
         * The peer version lives in px[1..2], not in the body. Use px[2]
         * (the minor version byte) for classification. */
        if (px[2] == 0x00) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "SSLv3.0");
        } else if (px[2] == 0x01) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.0");
        } else if (px[2] == 0x02) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.1");
        } else if (px[2] == 0x03) {
            /**
             * NOTE: (TRICK)
             * In practice, our default probe can support normal TLS from
             * version 1.0 to version 1.2 . If we got a `protocol version` alert
             * from version 1.2, we can infer that the server only support
             * version 1.3. This could help us to identify the servers which
             * only support TLSv1.3 with our default payload--a very rare
             * condition. But it cannot test if the servers support TLSv1.3.
             *
             * 70 is an ALERT description for Protocol Version
             */
            if (!tlshello_conf.support_tls1_3 && px[6] == 70) {
                safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.3");
            } else {
                safe_strcpy(item->classification, OUT_CLS_SIZE, "TLSv1.2");
            }
        } else {
            /**
             * 1. TLSv1.3 cannot be identified in this field.
             * 2. Our current probe cannot get normal response from TLSv1.3.
             */
            item->level = OUT_FAILURE;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");
            /*no further info*/
            return 0;
        }
#ifndef NOT_FOUND_PCRE2

        if (tlshello_conf.compiled_re) {
            item->level = OUT_FAILURE;
            safe_strcpy(item->reason, OUT_RSN_SIZE, "regex not matched");
        }
#endif

        item->level = OUT_SUCCESS;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol matched");
        dach_append_str(&item->probe_report, "type", "alert",
                        sizeof("alert") - 1);
        dach_set_int(&item->probe_report, "level", px[5]);
        dach_set_int(&item->probe_report, "desc", px[6]);

        /*we can do further regex matching here*/

        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "not TLS");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "protocol not matched");

    return 0;
}

Probe TlsHelloProbe = {
    .name       = "tls-hello",
    .type       = ProbeType_TCP,
    .params     = tlshello_parameters,
    .short_desc = "Try to get TLS Server Hello and identify the version or do "
                  "regex matching.",
    .desc =
        "TlsHello Probe sends an simple version-universal ClientHello and "
        "gets the first response from target port. It tries to identify if "
        "the service is TLS/SSL and check the TLS/SSL version. Further "
        "more, we can set regex to match some text from the response. This "
        "helps us to find some interesting devices or upper-layer protocol "
        "from the cert or domains of the response.\n"
        "NOTE1: TlsHello is TCP type of probe with just one payload so "
        "that it could work in very high scan rate. We could use JARM "
        "probe which has 10 payloads to get more info about TLS/SSL itself "
        "or we can use TlsState probe which is in type of STATE to get "
        "info about upper-layer service like HTTPS.\n"
        "NOTE2: TlsHello is designed to prioritize compatibility with "
        "all TLS/SSL version. That's why it uses a payload with supported"
        "version from TLSv1.0 to TLSv1.2 or TLSv1.3 as payload. So this "
        "payload maybe unsafe from the perspective of TLS.\n"
        "NOTE3: The domain and cert info is encrypted in TLSv1.3, so the "
        "default probe payload doesn't support TLSv1.3 and also cannot test if "
        "the server supports TLSv1.3. But we can set `-tls13` to use a "
        "TLSv1.3-compatible payload as probe. But TlsHello will not do regex "
        "matching from it if the server responses a TLSv1.3 ServerHello.\n"
        "Dependencies: PCRE2 for regex.",

    .init_cb               = &tlshello_init,
    .make_payload_cb       = &tlshello_make_payload,
    .get_payload_length_cb = &tlshello_get_payload_length,
    .handle_response_cb    = &tlshello_handle_reponse,
    .close_cb              = &probe_close_nothing,
};