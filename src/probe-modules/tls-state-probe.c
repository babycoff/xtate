/**
 * Originally born from the broken one: https://github.com/bi-zone/masscan-ng
 * I fixed some errors, bugs and done some updates. (So exhausted...)
 * Now it supports multi data exchange after hello over TLS and more functions.
 *
 * Modified and Created by Alvin Chen 2024
 */
#ifndef NOT_FOUND_OPENSSL

#include "probe-modules.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../xconf.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../output-modules/output-modules.h"
#include "../util-out/logger.h"
#include "../util-misc/ssl-help.h"
#include "../util-misc/misc.h"

#define TSP_BIO_MEM_LIMIT  16384
#define TSP_DATA_INIT_SIZE 4096
#define TSP_EXT_TGT_IDX    0

/**
 * TlsStateProbe's internal state.
 * Diff from TLS's.
 */
enum TSP_State {
    TSP_STATE_HANDSHAKE = 0, /*init state: still in handshaking*/
    TSP_STATE_SAY_HELLO,     /*our turn to say hello*/
    TSP_STATE_RECV_DATA,     /*waiting for data*/
    TSP_STATE_NEED_CLOSE,    /*unexpected state that need to close conn*/
};

static const char *_tsp_state_to_string(enum TSP_State state) {
    switch (state) {
        case TSP_STATE_HANDSHAKE:
            return "TSP_HANDSHAKE";
        case TSP_STATE_SAY_HELLO:
            return "TSP_SAY_HELLO";
        case TSP_STATE_RECV_DATA:
            return "TSP_RECV_DATA";
        case TSP_STATE_NEED_CLOSE:
            return "TSP_NEED_CLOSE";

        default:
            return "UNKN_TSP_STATE";
    }
}

/*for internal x-ref*/
extern Probe          TlsStateProbe;
/*save Output*/
static const OutConf *_tls_out;
/*public SSL obj for all conn*/
static SSL_CTX       *_general_ssl_ctx;

struct TlsState {
    OSSL_HANDSHAKE_STATE handshake_state;
    ProbeState           substate;
    unsigned char       *data;
    size_t               data_size;
    SSL                 *ssl;
    BIO                 *rbio;
    BIO                 *wbio;
    unsigned             have_dump_version : 1;
    unsigned             have_dump_subject : 1;
    unsigned             have_dump_cipher  : 1;
    unsigned             have_dump_cert    : 1;
};

struct TlsStateConf {
    Probe   *subprobe;
    char    *subprobe_args;
    char    *sni;
    unsigned char *alpn;
    size_t         alpn_len;
    unsigned dump_subject   : 1;
    unsigned dump_version   : 1;
    unsigned dump_cipher    : 1;
    unsigned ssl_keylog     : 1;
    unsigned dump_cert      : 1;
    unsigned fail_handshake : 1;
};

static struct TlsStateConf tlsstate_conf = {0};

static ConfRes SET_subprobe(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlsstate_conf.subprobe = get_probe_module_by_name(value);
    if (!tlsstate_conf.subprobe) {
        LOG(LEVEL_ERROR, "invalid name of subprobe: %s.\n", value);
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_subprobe_args(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    size_t len = strlen(value) + 1;
    FREE(tlsstate_conf.subprobe_args);
    tlsstate_conf.subprobe_args = CALLOC(1, len);
    memcpy(tlsstate_conf.subprobe_args, value, len);

    return Conf_OK;
}

static ConfRes SET_sni(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    size_t len = strlen(value);
    if (len == 0 || len > 255) {
        LOG(LEVEL_ERROR,
            "sni must contain 1..255 bytes of DNS host name, got %u bytes\n",
            (unsigned)len);
        return Conf_ERR;
    }

    FREE(tlsstate_conf.sni);
    tlsstate_conf.sni = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_alpn(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    const char *p = value;
    size_t      cap = strlen(value) + 2;
    unsigned char *wire = MALLOC(cap);
    size_t         n = 0;

    while (*p) {
        while (*p == ',' || isspace((unsigned char)*p))
            p++;
        if (!*p)
            break;

        const char *start = p;
        while (*p && *p != ',' && !isspace((unsigned char)*p))
            p++;
        size_t len = (size_t)(p - start);
        if (len == 0 || len > 255 || n + 1 + len > 65535) {
            FREE(wire);
            LOG(LEVEL_ERROR, "invalid or oversized ALPN protocol list\n");
            return Conf_ERR;
        }

        wire[n++] = (unsigned char)len;
        memcpy(wire + n, start, len);
        n += len;
    }

    if (n == 0) {
        FREE(wire);
        LOG(LEVEL_ERROR, "empty ALPN protocol list\n");
        return Conf_ERR;
    }

    FREE(tlsstate_conf.alpn);
    tlsstate_conf.alpn     = wire;
    tlsstate_conf.alpn_len = n;
    return Conf_OK;
}

static ConfRes SET_ssl_keylog(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlsstate_conf.ssl_keylog = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_dump_version(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlsstate_conf.dump_version = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_dump_cipher(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlsstate_conf.dump_cipher = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_dump_cert(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlsstate_conf.dump_cert = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_dump_subject(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlsstate_conf.dump_subject = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_fail_handshake(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tlsstate_conf.fail_handshake = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam tlsstate_parameters[] = {
    {"subprobe",
     SET_subprobe,
     Type_ARG,
     {"sub-probe-module", 0},
     "Specifies a ProbeModule as subprobe of TlsState Probe."},
    {"subprobe-arg",
     SET_subprobe_args,
     Type_ARG,
     {"subprobe-args", "subarg", "subargs", 0},
     "Specifies arguments for subprobe.\n"
     "NOTE: Use double/single quotes and backslashes to handle params with "
     "spaces in nesting."},
    {"sni",
     SET_sni,
     Type_ARG,
     {"server-name", "servername", 0},
     "TLS SNI host name sent in ClientHello.  Targets are IP addresses, so "
     "this is one explicit host name applied to every target in the run; "
     "leave unset for no SNI.  Useful when scanning IPs that belong to one "
     "CDN/virtual host."},
    {"alpn",
     SET_alpn,
     Type_ARG,
     {"alpn-protos", "alpn-proto", 0},
     "Comma/space separated ALPN protocol list, e.g. `h2,http/1.1`.  The "
     "order is preserved.  Leave unset for no ALPN extension."},
    {"ssl-keylog",
     SET_ssl_keylog,
     Type_FLAG,
     {"key-log", 0},
     "Record the SSL key log to result as INFO."},
    {"dump-version",
     SET_dump_version,
     Type_FLAG,
     {"version", 0},
     "Record SSL/TLS version to results as INFO."},
    {"dump-cipher",
     SET_dump_cipher,
     Type_FLAG,
     {"cipher", 0},
     "Record cipher suites of SSL/TLS connection to results as INFO."},
    {"dump-cert",
     SET_dump_cert,
     Type_FLAG,
     {"cert", 0},
     "Record X509 cert info of SSL/TLS server to results in base64 format as"
     " INFO."},
    {"dump-subject",
     SET_dump_subject,
     Type_FLAG,
     {"subject", 0},
     "Record X509 subject info of SSL/TLS server to results as INFO."},
    {"fail-handshake",
     SET_fail_handshake,
     Type_FLAG,
     {"handshake-fail", 0},
     "Output TLS handshake failed as FAILED results. Default is INFO."},

    {0}};

static void ssl_keylog_cb(const SSL *ssl, const char *line) {
    ProbeTarget *tgt = SSL_get_ex_data(ssl, TSP_EXT_TGT_IDX);
    if (!tgt)
        return;

    OutItem item = {
        .target.ip_proto  = tgt->target.ip_proto,
        .target.ip_them   = tgt->target.ip_them,
        .target.port_them = tgt->target.port_them,
        .target.ip_me     = tgt->target.ip_me,
        .target.port_me   = tgt->target.port_me,
        .level            = OUT_SUCCESS,
    };

    safe_strcpy(item.classification, OUT_CLS_SIZE, "tls info");
    dach_append_str(&item.probe_report, "key_log", line, strlen(line));

    output_result(_tls_out, &item);
}

static void ssl_info_cb(const SSL *ssl, int where, int ret) {
    if (where & SSL_CB_ALERT) {
        ProbeTarget *tgt = SSL_get_ex_data(ssl, TSP_EXT_TGT_IDX);
        if (!tgt)
            return;

        OutItem item = {
            .target.ip_proto  = tgt->target.ip_proto,
            .target.ip_them   = tgt->target.ip_them,
            .target.port_them = tgt->target.port_them,
            .target.ip_me     = tgt->target.ip_me,
            .target.port_me   = tgt->target.port_me,
            .level            = OUT_INFO,
        };

        safe_strcpy(item.classification, OUT_CLS_SIZE, "tls info");
        dach_printf(&item.probe_report, "openssl alert", "0x%04x %s: %s", ret,
                    SSL_alert_type_string_long(ret),
                    SSL_alert_desc_string_long(ret));

        output_result(_tls_out, &item);
    }
}

static bool output_subject_info(OutConf *out, ProbeTarget *target, SSL *ssl) {
    int        res;
    unsigned   count;
    char       s_names[512];
    DataLink  *link;
    BIO       *bio                         = NULL;
    X509      *x509_cert                   = NULL;
    X509_NAME *x509_subject_name           = NULL;
    STACK_OF(GENERAL_NAME) *x509_alt_names = NULL;

    x509_cert = SSL_get_peer_certificate(ssl);
    if (x509_cert == NULL) {
        return false;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOG(LEVEL_WARN, "(TSP output_subject_info) BIO_new failed\n");
        X509_free(x509_cert);
        return false;
    }

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.port_them = target->target.port_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_me   = target->target.port_me,
        .level            = OUT_SUCCESS,
    };
    safe_strcpy(item.classification, OUT_CLS_SIZE, "tls info");

    x509_subject_name = X509_get_subject_name(x509_cert);
    if (x509_subject_name != NULL) {
        int i_name;
        count = 0;
        for (i_name = 0; i_name < X509_NAME_entry_count(x509_subject_name);
             i_name++) {
            X509_NAME_ENTRY *name_entry = NULL;
            ASN1_OBJECT     *fn         = NULL;
            ASN1_STRING     *val        = NULL;

            name_entry = X509_NAME_get_entry(x509_subject_name, i_name);
            if (name_entry == NULL) {
                LOG(LEVEL_WARN,
                    "(TSP output_subject_info) X509_NAME_get_entry failed on "
                    "%d\n",
                    i_name);
                continue;
            }
            fn = X509_NAME_ENTRY_get_object(name_entry);
            if (fn == NULL) {
                LOG(LEVEL_WARN,
                    "(TSP output_subject_info) X509_NAME_ENTRY_get_object "
                    "failed on %d\n",
                    i_name);
                continue;
            }
            val = X509_NAME_ENTRY_get_data(name_entry);
            if (val == NULL) {
                LOG(LEVEL_WARN,
                    "(TSP output_subject_info) X509_NAME_ENTRY_get_data failed "
                    "on %d\n",
                    i_name);
                continue;
            }
            if (NID_commonName == OBJ_obj2nid(fn)) {
                if (count) {
                    BIO_printf(bio, ", ");
                }
                count++;
                res = ASN1_STRING_print_ex(bio, val, 0);
                if (res < 0) {
                    LOG(LEVEL_WARN,
                        "(TSP output_subject_info) ASN1_STRING_print_ex failed "
                        "with error %d on %d\n",
                        res, i_name);
                    BIO_printf(bio, "<can't get cn>");
                }
            }
        }
    } else {
        LOG(LEVEL_WARN,
            "(TSP output_subject_info) X509_get_subject_name failed\n");
    }

    link = dach_new_link(&item.probe_report, "subject name",
                         DACH_DEFAULT_DATA_SIZE, LinkType_String);

    while (true) {
        res = BIO_read(bio, s_names, sizeof(s_names));
        if (res > 0) {
            link = dach_append_by_link(link, s_names, res);
        } else if (res == 0 || res == -1) {
            break;
        } else {
            LOG(LEVEL_WARN, "(TSP output_subject_info) BIO_read failed: %d\n",
                res);
            break;
        }
    }

    count = 0;
    x509_alt_names =
        X509_get_ext_d2i(x509_cert, NID_subject_alt_name, NULL, NULL);
    if (x509_alt_names != NULL) {
        int i_name = 0;
        for (i_name = 0; i_name < sk_GENERAL_NAME_num(x509_alt_names);
             i_name++) {
            GENERAL_NAME *x509_alt_name;

            x509_alt_name = sk_GENERAL_NAME_value(x509_alt_names, i_name);
            if (x509_alt_name == NULL) {
                LOG(LEVEL_WARN,
                    "(TSP output_subject_info) sk_GENERAL_NAME_value failed on "
                    "%d\n",
                    i_name);
                continue;
            }
            if (count) {
                BIO_printf(bio, ", ");
            }
            count++;
            res = GENERAL_NAME_simple_print(bio, x509_alt_name);
            if (res < 0) {
                LOG(LEVEL_DEBUG,
                    "(TSP output_subject_info) GENERAL_NAME_simple_print "
                    "failed with error %d on "
                    "%d\n",
                    res, i_name);
                BIO_printf(bio, "<can't get alt>");
            }
        }
        sk_GENERAL_NAME_pop_free(x509_alt_names, GENERAL_NAME_free);
    }

    link = dach_new_link(&item.probe_report, "alt name", DACH_DEFAULT_DATA_SIZE,
                         LinkType_String);

    while (true) {
        res = BIO_read(bio, s_names, sizeof(s_names));
        if (res > 0) {
            link = dach_append_by_link(link, s_names, res);
        } else if (res == 0 || res == -1) {
            break;
        } else {
            LOG(LEVEL_WARN, "(TSP output_subject_info) BIO_read failed: %d\n",
                res);
            break;
        }
    }

    output_result(out, &item);

    // error2:
    BIO_free(bio);
    X509_free(x509_cert);
    return true;
}

static bool output_x502_cert(OutConf *out, ProbeTarget *target, SSL *ssl) {
    STACK_OF(X509) * sk_x509_certs;
    DataLink *link;
    int       i_cert;
    int       res;
    char      s_base64[2048];

    sk_x509_certs = SSL_get_peer_cert_chain(ssl);
    if (sk_x509_certs == NULL) {
        return false;
    }

    for (i_cert = 0; i_cert < sk_X509_num(sk_x509_certs); i_cert++) {
        OutItem item = {
            .target.ip_proto  = target->target.ip_proto,
            .target.ip_them   = target->target.ip_them,
            .target.port_them = target->target.port_them,
            .target.ip_me     = target->target.ip_me,
            .target.port_me   = target->target.port_me,
            .level            = OUT_SUCCESS,
        };

        safe_strcpy(item.classification, OUT_CLS_SIZE, "tls info");

        X509 *x509_cert  = NULL;
        BIO  *bio_base64 = NULL;
        BIO  *bio_mem    = NULL;

        x509_cert = sk_X509_value(sk_x509_certs, i_cert);
        if (x509_cert == NULL) {
            LOG(LEVEL_WARN,
                "(TSP output_x502_cert) sk_X509_value failed on %d\n", i_cert);
            continue;
        }

        bio_base64 = BIO_new(BIO_f_base64());
        if (bio_base64 == NULL) {
            LOG(LEVEL_WARN,
                "(TSP output_x502_cert) BIO_new(base64) failed on %d\n",
                i_cert);
            continue;
        }
        BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

        bio_mem = BIO_new(BIO_s_mem());
        if (bio_mem == NULL) {
            LOG(LEVEL_WARN,
                "(TSP output_x502_cert) BIO_new(bio_mem) failed on %d\n",
                i_cert);
            BIO_free(bio_base64);
            continue;
        }
        bio_base64 = BIO_push(bio_base64, bio_mem);

        res = i2d_X509_bio(bio_base64, x509_cert);
        if (res != 1) {
            LOG(LEVEL_WARN,
                "(TSP output_x502_cert) i2d_X509_bio failed with error %d on "
                "%d\n",
                res, i_cert);
            BIO_free(bio_mem);
            BIO_free(bio_base64);
            continue;
        }
        res = BIO_flush(bio_base64);
        if (res != 1) {
            LOG(LEVEL_WARN,
                "(TSP output_x502_cert) BIO_flush failed with error %d on %d\n",
                res, i_cert);
            BIO_free(bio_mem);
            BIO_free(bio_base64);
            continue;
        }

        /*cert is a little bit large*/
        link = dach_new_link_printf(&item.probe_report, 2048, LinkType_String,
                                    "cert_%d", i_cert + 1);

        while (true) {
            res = BIO_read(bio_mem, s_base64, sizeof(s_base64));
            if (res > 0) {
                link = dach_append_by_link(link, s_base64, res);
            } else if (res == 0 || res == -1) {
                break;
            } else {
                LOG(LEVEL_WARN, "(TSP output_x502_cert) BIO_read failed: %d\n",
                    res);
                break;
            }
        }

        output_result(out, &item);

        BIO_free(bio_mem);
        BIO_free(bio_base64);
    }

    return true;
}

static bool output_cipher_suite(OutConf *out, ProbeTarget *target, SSL *ssl) {
    const SSL_CIPHER *ssl_cipher;
    uint16_t          cipher_suite;

    ssl_cipher = SSL_get_current_cipher(ssl);
    if (ssl_cipher == NULL) {
        ssl_cipher = SSL_get_pending_cipher(ssl);
        if (ssl_cipher == NULL) {
            return false;
        }
    }

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.port_them = target->target.port_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_me   = target->target.port_me,
        .level            = OUT_SUCCESS,
    };

    safe_strcpy(item.classification, OUT_CLS_SIZE, "tls info");

    cipher_suite = SSL_CIPHER_get_protocol_id(ssl_cipher);
    dach_printf(&item.probe_report, "cipher", "0x%x", cipher_suite);

    output_result(_tls_out, &item);

    return true;
}

static bool output_tls_version(OutConf *out, ProbeTarget *target, SSL *ssl) {
    int version = SSL_version(ssl);

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.port_them = target->target.port_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_me   = target->target.port_me,
        .level            = OUT_SUCCESS,
    };

    switch (version) {
        case SSL3_VERSION:
            dach_append_str(&item.probe_report, "version", "SSLv3.0",
                            sizeof("SSLv3.0") - 1);
            break;
        case TLS1_VERSION:
            dach_append_str(&item.probe_report, "version", "TLSv1.0",
                            sizeof("TLSv1.0") - 1);
            break;
        case TLS1_1_VERSION:
            dach_append_str(&item.probe_report, "version", "TLSv1.1",
                            sizeof("TLSv1.1") - 1);
            break;
        case TLS1_2_VERSION:
            dach_append_str(&item.probe_report, "version", "TLSv1.2",
                            sizeof("TLSv1.2") - 1);
            break;
        case TLS1_3_VERSION:
            dach_append_str(&item.probe_report, "version", "TLSv1.3",
                            sizeof("TLSv1.3") - 1);
            break;
        default:
            dach_append_str(&item.probe_report, "version", "Other",
                            sizeof("Other") - 1);
    }

    safe_strcpy(item.classification, OUT_CLS_SIZE, "tls info");
    output_result(_tls_out, &item);

    return true;
}

static void _extend_buffer(unsigned char **buf, size_t *buf_len) {
    LOG(LEVEL_DETAIL, "(TSP BUFFER extending...) >>>\n");
    unsigned char *tmp_ptr;
    tmp_ptr  = REALLOC(*buf, *buf_len * 2);
    *buf     = tmp_ptr;
    *buf_len = *buf_len * 2;
}

/*init public SSL_CTX*/
static bool tlsstate_init(const XConf *xconf) {
    if (!tlsstate_conf.subprobe ||
        tlsstate_conf.subprobe->type != ProbeType_STATE) {
        LOG(LEVEL_ERROR, "TlsStateProbe need a subprobe in STATE type.\n");
        return false;
    }

    /*save `out` handler*/
    _tls_out = &xconf->out_conf;

    const SSL_METHOD *meth;
    SSL_CTX          *ctx;
    int               res;

    LOG(LEVEL_DETAIL, "(TSP Global INIT) >>>\n");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /*support cryptographic algorithms from SSLv3.0 to TLSv1.3*/
    meth = TLS_method();
    if (meth == NULL) {
        LOG(LEVEL_ERROR, "(TSP Global INIT) TLS_method error\n");
        LOGopenssl(LEVEL_ERROR);
        goto error0;
    }

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        LOG(LEVEL_ERROR, "(TSP Global INIT) SSL_CTX_new error\n");
        LOGopenssl(LEVEL_ERROR);
        goto error0;
    }

    /*no verification for server*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /*support all versions*/
    res = SSL_CTX_set_min_proto_version(ctx, 0);
    if (res != 1) {
        LOG(LEVEL_WARN,
            "(TSP Global INIT) SSL_CTX_set_min_proto_version error %d\n", res);
    }
    SSL_CTX_set_max_proto_version(ctx, 0);
    if (res != 1) {
        LOG(LEVEL_WARN,
            "(TSP Global INIT) SSL_CTX_set_max_proto_version error %d\n", res);
    }

    /*security level 0 means: everything is permitted*/
    SSL_CTX_set_security_level(ctx, 0);

    /*support all ciphers and all "no ciphers" in TLS versions under 1.2*/
    res = SSL_CTX_set_cipher_list(ctx, "ALL:eNULL");
    if (res != 1) {
        LOG(LEVEL_WARN, "(TSP Global INIT) SSL_CTX_set_cipher_list error %d\n",
            res);
    }

    /*ciphersuites allowed in TLSv1.3. (ALL & in order)*/
    res = SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:"
                                        "TLS_AES_256_GCM_SHA384:"
                                        "TLS_CHACHA20_POLY1305_SHA256:"
                                        "TLS_AES_128_CCM_SHA256:"
                                        "TLS_AES_128_CCM_8_SHA256");
    if (res != 1) {
        LOG(LEVEL_WARN, "(TSP Global INIT) SSL_CTX_set_ciphersuites error %d\n",
            res);
    }

    /*this allows our probe to be able to handshake with old server in version
     * of TLSv1.0*/
    SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

    /**
     * set TLS key logging callback
     * typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);
     * */
    if (tlsstate_conf.ssl_keylog) {
        SSL_CTX_set_keylog_callback(ctx, ssl_keylog_cb);
    }

    _general_ssl_ctx = ctx;

    if (tlsstate_conf.subprobe_args && tlsstate_conf.subprobe->params) {
        if (conf_set_params_from_substr(NULL, tlsstate_conf.subprobe->params,
                                        tlsstate_conf.subprobe_args)) {
            LOG(LEVEL_ERROR, "subparam parsing of subprobe of TlsState.\n");
            goto error0;
        }
    }

    /**
     * multi-probe Multi_Direct
     * Pass multi-probe attributes of subprobe
     * Well...ugly but works.
     * */
    MultiMode *mode = (MultiMode *)&TlsStateProbe.multi_mode;
    unsigned  *num  = (unsigned *)&TlsStateProbe.multi_num;
    *mode           = tlsstate_conf.subprobe->multi_mode;
    *num            = tlsstate_conf.subprobe->multi_num;

    /*init for subprobe*/
    return tlsstate_conf.subprobe->init_cb(xconf);

error0:
    return false;
}

static void tlsstate_close() {
    LOG(LEVEL_DETAIL, "(TSP CLOSE) >>>\n");

    tlsstate_conf.subprobe->close_cb();

    if (_general_ssl_ctx) {
        SSL_CTX_free(_general_ssl_ctx);
        _general_ssl_ctx = NULL;
    }

    return;
}

/*init SSL struct*/
static bool tlsstate_conn_init(ProbeState *state, ProbeTarget *target) {
    int              res;
    SSL             *ssl;
    BIO             *rbio;
    BIO             *wbio;
    unsigned char   *data;
    struct TlsState *tls_state;

    LOG(LEVEL_DETAIL, "(TSP Conn INIT) >>>\n");

    if (_general_ssl_ctx == NULL) {
        goto error0;
    }

    /*buffer for BIO*/
    data      = MALLOC(TSP_DATA_INIT_SIZE);
    tls_state = CALLOC(1, sizeof(struct TlsState));

    rbio = BIO_new(BIO_s_mem());
    if (rbio == NULL) {
        LOG(LEVEL_ERROR, "(TSP Conn INIT) BIO_new(read) error\n");
        LOGopenssl(LEVEL_ERROR);
        goto error1;
    }

    wbio = BIO_new(BIO_s_mem());
    if (wbio == NULL) {
        LOG(LEVEL_ERROR, "(TSP Conn INIT) BIO_new(write) error\n");
        LOGopenssl(LEVEL_ERROR);
        goto error2;
    }

    ssl = SSL_new(_general_ssl_ctx);
    if (ssl == NULL) {
        LOG(LEVEL_ERROR, "(TSP Conn INIT) SSL_new error\n");
        LOGopenssl(LEVEL_ERROR);
        goto error3;
    }

    /*client mode*/
    SSL_set_connect_state(ssl);
    /*bind BIO interfaces and SSL obj*/
    SSL_set_bio(ssl, rbio, wbio);

    /*Optional SNI/ALPN. Targets are IPs, so SNI is an explicit single name
     * selected by the operator for this run. */
    if (tlsstate_conf.sni) {
        if (SSL_set_tlsext_host_name(ssl, tlsstate_conf.sni) != 1) {
            LOG(LEVEL_WARN, "(TSP Conn INIT) SSL_set_tlsext_host_name error\n");
        }
    }
    if (tlsstate_conf.alpn_len) {
        if (SSL_set_alpn_protos(ssl, tlsstate_conf.alpn,
                                (unsigned)tlsstate_conf.alpn_len) != 0) {
            LOG(LEVEL_WARN, "(TSP Conn INIT) SSL_set_alpn_protos error\n");
        }
    }

    /*save `target` to SSL object*/
    ProbeTarget *tgt;
    tgt                   = MALLOC(sizeof(ProbeTarget));
    tgt->target.ip_proto  = target->target.ip_proto;
    tgt->target.ip_them   = target->target.ip_them;
    tgt->target.port_them = target->target.port_them;
    tgt->target.ip_me     = target->target.ip_me;
    tgt->target.port_me   = target->target.port_me;
    tgt->cookie           = target->cookie;
    tgt->index            = target->index;

    res = SSL_set_ex_data(ssl, TSP_EXT_TGT_IDX, tgt);
    if (res != 1) {
        LOG(LEVEL_WARN, "(TSP Conn INIT) SSL_set_ex_data error\n");
        goto error4;
    }

    /*set info cb to print status changing, alert and errors*/
    SSL_set_info_callback(ssl, ssl_info_cb);

    /*keep important struct in probe state*/
    tls_state->ssl             = ssl;
    tls_state->rbio            = rbio;
    tls_state->wbio            = wbio;
    tls_state->data            = data;
    tls_state->data_size       = TSP_DATA_INIT_SIZE;
    tls_state->handshake_state = TLS_ST_BEFORE; /*state for openssl*/

    state->data = tls_state;

    /**
     * Do conn init for subprobe.
     * FIXME:
     * This shouldn't be happened here but after TLS handshaking.
     * */
    return tlsstate_conf.subprobe->conn_init_cb(&tls_state->substate, target);

    // SSL_set_ex_data(ssl, 1, NULL);
// error7:
// SSL_set_ex_data(ssl, 0, NULL);
error4:
    FREE(tgt);
    SSL_free(ssl);
error3:
    BIO_free(wbio);
error2:
    BIO_free(rbio);
error1:
    FREE(data);
    FREE(tls_state);
error0:

    return false;
}

static void tlsstate_conn_close(ProbeState *state, ProbeTarget *target) {
    LOG(LEVEL_DETAIL, "(TSP Conn CLOSE) >>>\n");

    if (!state->data)
        return;

    struct TlsState *tls_state = state->data;

    if (!tls_state)
        return;

    /*do conn close for subprobe*/
    tlsstate_conf.subprobe->conn_close_cb(&tls_state->substate, target);

    if (tls_state->ssl) {
        /*cleanup ex data in SSL obj*/
        void *ex_data = SSL_get_ex_data(tls_state->ssl, TSP_EXT_TGT_IDX);
        FREE(ex_data);
        SSL_free(tls_state->ssl);
        tls_state->ssl  = NULL;
        tls_state->rbio = NULL;
        tls_state->wbio = NULL;
    }

    FREE(tls_state->data);
    tls_state->data_size = 0;

    FREE(tls_state);
    state->data = NULL;
}

static void tlsstate_make_hello(DataPass *pass, ProbeState *state,
                                ProbeTarget *target) {
    LOG(LEVEL_DETAIL, "(TSP Make HELLO) >>>\n");

    if (state->data == NULL)
        goto error1;

    size_t           offset    = 0;
    struct TlsState *tls_state = state->data;

    ERR_clear_error();
    int res    = SSL_do_handshake(tls_state->ssl);
    int res_ex = SSL_ERROR_NONE;
    if (res < 0) {
        res_ex = SSL_get_error(tls_state->ssl, res);
    }

    if (res == 1) {
        // if success, but its impossible
    } else if (res < 0 && res_ex == SSL_ERROR_WANT_READ) {
        offset = 0;
        while (true) {
            /*extend if buffer is not enough*/
            if (tls_state->data_size - offset <= 0) {
                _extend_buffer(&tls_state->data, &tls_state->data_size);
            }

            /*get ClientHello here*/
            res = BIO_read(tls_state->wbio, tls_state->data + offset,
                           (int)(tls_state->data_size - offset));
            if (res > 0) {
                LOG(LEVEL_DETAIL, "(TSP Make HELLO) BIO_read: %d\n", res);
                offset += (size_t)res;
            } else if (res == 0 || res == -1) {
                LOG(LEVEL_DETAIL, "(TSP Make HELLO) BIO_read: %d\n", res);
                break;
            } else {
                LOG(LEVEL_WARN, "(TSP Make HELLO) BIO_read failed: %d\n", res);
                LOGopenssl(LEVEL_WARN);
                goto error1;
            }
        }
    } else {
        LOG(LEVEL_WARN,
            "(TSP Make HELLO) SSL_do_handshake failed: %d, ex_error: %d\n", res,
            res_ex);
        LOGopenssl(LEVEL_WARN);
        goto error1;
    }

    /*save state for openssl*/
    tls_state->handshake_state = SSL_get_state(tls_state->ssl);

    /*telling underlayer to send ClientHello*/
    datapass_set_data(pass, tls_state->data, offset, true);

    return;
error1:
    pass->data     = NULL;
    pass->len      = 0;
    pass->is_close = 1;
    return;
}

static unsigned tlsstate_parse_response(DataPass *pass, ProbeState *state,
                                        OutConf *out, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned             sizeof_px) {
    LOG(LEVEL_DETAIL, "(TSP Parse RESPONSE) >>>\n");

    struct TlsState *tls_state = state->data;

    int      res, res_ex;
    bool     is_continue;
    unsigned ret = 0;

    if (state->state == TSP_STATE_NEED_CLOSE) {
        is_continue = false;
    } else {
        is_continue = true;
    }

    if (is_continue && px != NULL && sizeof_px != 0) {
        size_t offset = 0;
        // uint64_t now_time = pixie_gettime();

        res = 0;
        while (offset < sizeof_px) {
            res = BIO_write(
                tls_state->rbio, px + offset,
                (unsigned int)min(TSP_BIO_MEM_LIMIT, sizeof_px - offset));
            LOG(LEVEL_DETAIL, "(TSP Parse RESPONSE) BIO_write: %d \n", res);
            if (res > 0) {
                offset += (size_t)res;
            } else {
                LOG(LEVEL_WARN, "(TSP Parse RESPONSE) BIO_write failed: %d\n",
                    res);
                /*close connection*/
                pass->data     = NULL;
                pass->len      = 0;
                pass->is_close = 1;
                return ret;
            }
        }

        // now_time = pixie_gettime() - now_time;
        // if (sizeof_px > TSP_BIO_MEM_LIMIT || now_time > 1000000) {
        //     LOGip(LEVEL_WARN, target->target.ip_them,
        //     target->target.port_them,
        //           "(TSP Parse RESPONSE) len px: 0x%" PRIxPTR ", time: "
        //           PRIu64 " millis\n", sizeof_px, now_time * 1000);
        //     LOG(LEVEL_WARN, "(TSP Parse RESPONSE) offset: 0x%" PRIxPTR ", res
        //     = %d\n",
        //         offset, res);
        //     if (sizeof_px > 3) {
        //         LOG(LEVEL_WARN, "(TSP Parse RESPONSE) dump: %02X %02X %02X
        //         %02X\n",
        //             px[0], px[1], px[2], px[3]);
        //     }
        // }
    }

    while (is_continue) {
        switch (state->state) {
            /*still in handshake*/
            case TSP_STATE_HANDSHAKE:

                ERR_clear_error();
                res    = SSL_do_handshake(tls_state->ssl);
                res_ex = SSL_ERROR_NONE;

                if (res < 0) {
                    res_ex = SSL_get_error(tls_state->ssl, res);
                }

                tls_state->handshake_state = SSL_get_state(tls_state->ssl);

                if (tls_state->handshake_state != TLS_ST_BEFORE &&
                    tls_state->handshake_state != TLS_ST_CW_CLNT_HELLO) {
                    /*output version*/
                    if (tlsstate_conf.dump_version &&
                        !tls_state->have_dump_version) {
                        output_tls_version(out, target, tls_state->ssl);
                        tls_state->have_dump_version = 1;
                    }
                    /*output cipher suites*/
                    if (tlsstate_conf.dump_cipher &&
                        !tls_state->have_dump_cipher) {
                        if (output_cipher_suite(out, target, tls_state->ssl))
                            tls_state->have_dump_cipher = 1;
                    }
                }

                /*output X.509 cert info*/
                if (tlsstate_conf.dump_cert && !tls_state->have_dump_cert) {
                    if (output_x502_cert(out, target, tls_state->ssl))
                        tls_state->have_dump_cert = 1;
                }

                /*output X.509 subject info*/
                if (tlsstate_conf.dump_subject &&
                    !tls_state->have_dump_subject) {
                    if (output_subject_info(out, target, tls_state->ssl))
                        tls_state->have_dump_subject = 1;
                }

                // finished handshake
                if (res == 1) {
                    // handshake successfully
                    if (tls_state->handshake_state == TLS_ST_OK) {
                        /*We also can do conn init for subprobe here,
                        but I must know exactly whether subprobe has been
                        inited.*/
                        state->state = TSP_STATE_SAY_HELLO;
                    } else {
                        LOG(LEVEL_WARN,
                            "(TSP Parse RESPONSE) Unknown handshake state %d\n",
                            tls_state->handshake_state);
                        state->state = TSP_STATE_NEED_CLOSE;
                    }
                } else if (res < 0 &&
                           res_ex == SSL_ERROR_WANT_READ) { // go on handshake

                    size_t offset = 0;

                    while (true) {
                        if (tls_state->data_size - offset <= 0) {
                            _extend_buffer(&tls_state->data,
                                           &tls_state->data_size);
                        }

                        res = BIO_read(
                            tls_state->wbio, tls_state->data + offset,
                            (unsigned int)(tls_state->data_size - offset));

                        if (res > 0) {
                            LOG(LEVEL_DETAIL,
                                "(TSP Parse RESPONSE: %s) BIO_read: %d\n",
                                _tsp_state_to_string(state->state), res);
                            offset += (size_t)res;
                        } else if (res == 0 || res == -1) {
                            LOG(LEVEL_DETAIL,
                                "(TSP Parse RESPONSE: %s) BIO_read: %d\n",
                                _tsp_state_to_string(state->state), res);
                            break;
                        } else {
                            LOG(LEVEL_WARN,
                                "(TSP Parse RESPONSE: %s) BIO_read failed: "
                                "%d\n",
                                _tsp_state_to_string(state->state), res);
                            state->state = TSP_STATE_NEED_CLOSE;
                            break;
                        }
                    }

                    if (state->state != TSP_STATE_NEED_CLOSE) {
                        datapass_set_data(pass, tls_state->data, offset, true);
                        is_continue = false;
                        break;
                    }
                } else { // cannot go on handshake

                    state->state = TSP_STATE_NEED_CLOSE;

                    LOG(LEVEL_DEBUG,
                        "(TSP Parse RESPONSE: %s) SSL_do_handshake failed: %d, "
                        "ex_error: %d\n",
                        _tsp_state_to_string(state->state), res, res_ex);
                    LOGopenssl(LEVEL_DEBUG);

                    OutItem item = {
                        .target.ip_proto  = target->target.ip_proto,
                        .target.ip_them   = target->target.ip_them,
                        .target.port_them = target->target.port_them,
                        .target.ip_me     = target->target.ip_me,
                        .target.port_me   = target->target.port_me,
                        .level = tlsstate_conf.fail_handshake ? OUT_FAILURE
                                                              : OUT_INFO,
                    };
                    safe_strcpy(item.classification, OUT_CLS_SIZE, "tls error");
                    safe_strcpy(item.reason, OUT_RSN_SIZE, "handshake failed");
                    output_result(_tls_out, &item);
                }
                break;

            //! It's time for subprobe to say hello
            case TSP_STATE_SAY_HELLO: {
                DataPass subpass = {0};
                tlsstate_conf.subprobe->make_hello_cb(
                    &subpass, &tls_state->substate, target);

                /**
                 * Maybe no hello to say and just wait for response.
                 * Or maybe just close the conn*/
                if (!subpass.data || !subpass.len) {
                    pass->is_close = subpass.is_close;
                    state->state   = TSP_STATE_RECV_DATA;
                    is_continue    = false;
                    break;
                }

                ERR_clear_error();
                res = SSL_write(tls_state->ssl, subpass.data, subpass.len);
                if (subpass.is_dynamic) {
                    FREE(subpass.data);
                    subpass.len = 0;
                }

                if (res <= 0) {
                    res_ex = SSL_get_error(tls_state->ssl, res);
                    LOG(LEVEL_WARN,
                        "(TSP Parse RESPONSE: %s) SSL_write error: %d %d\n",
                        _tsp_state_to_string(state->state), res, res_ex);
                    LOGopenssl(LEVEL_WARN);
                    state->state = TSP_STATE_NEED_CLOSE;
                } else {
                    LOG(LEVEL_DETAIL,
                        "(TSP Parse RESPONSE: %s) SSL_write: %d\n",
                        _tsp_state_to_string(state->state), res);
                    size_t offset = 0;
                    while (true) {
                        if (tls_state->data_size - offset <= 0) {
                            _extend_buffer(&tls_state->data,
                                           &tls_state->data_size);
                        }

                        res = BIO_read(
                            tls_state->wbio, tls_state->data + offset,
                            (unsigned int)(tls_state->data_size - offset));
                        if (res > 0) {
                            LOG(LEVEL_DETAIL,
                                "(TSP Parse RESPONSE: %s) BIO_read: %d\n",
                                _tsp_state_to_string(state->state), res);
                            offset += (size_t)res;
                        } else if (res == 0 || res == -1) {
                            LOG(LEVEL_DEBUG,
                                "(TSP Parse RESPONSE: %s) BIO_read: %d\n",
                                _tsp_state_to_string(state->state), res);
                            break;
                        } else {
                            LOG(LEVEL_WARN,
                                "(TSP Parse RESPONSE: %s) BIO_read failed: "
                                "%d\n",
                                _tsp_state_to_string(state->state), res);
                            LOGopenssl(LEVEL_WARN);
                            state->state = TSP_STATE_NEED_CLOSE;
                            break;
                        }
                    }
                    if (state->state != TSP_STATE_NEED_CLOSE) {
                        datapass_set_data(pass, tls_state->data, offset, true);
                        pass->is_close = subpass.is_close;
                        state->state   = TSP_STATE_RECV_DATA;
                        is_continue    = false;
                        break;
                    }
                }
                break;
            }

            //! Pass data to subprobe and go on to interact or close.
            case TSP_STATE_RECV_DATA: {
                /*It's rational to read all decoded data of SSL record from the
                 * buffer.*/
                size_t offset = 0;
                while (true) {
                    if (tls_state->data_size - offset <= 0) {
                        _extend_buffer(&tls_state->data, &tls_state->data_size);
                    }

                    ERR_clear_error();
                    res = SSL_read(tls_state->ssl, tls_state->data + offset,
                                   tls_state->data_size - offset);

                    if (res > 0) {
                        offset += res;
                    } else {
                        break;
                    }
                }

                /*have got decoded data from SSL record*/
                if (offset > 0) {
                    LOG(LEVEL_DETAIL, "(TSP Parse RESPONSE: %s) SSL_read: %d\n",
                        _tsp_state_to_string(state->state), offset);

                    DataPass subpass = {0};

                    ret = tlsstate_conf.subprobe->parse_response_cb(
                        &subpass, &tls_state->substate, out, target,
                        tls_state->data, offset);

                    /*Maybe no data and maybe just close*/
                    if (!subpass.data || !subpass.len) {
                        pass->is_close = subpass.is_close;
                        state->state   = TSP_STATE_RECV_DATA;
                        is_continue    = false;
                        break;
                    }

                    /*Subprobe has further data to send, encode it first*/
                    ERR_clear_error();
                    int sub_res =
                        SSL_write(tls_state->ssl, subpass.data, subpass.len);
                    if (subpass.is_dynamic) {
                        FREE(subpass.data);
                        subpass.len = 0;
                    }

                    if (sub_res <= 0) {
                        res_ex = SSL_get_error(tls_state->ssl, sub_res);
                        LOG(LEVEL_WARN,
                            "(TSP Parse RESPONSE: %s) SSL_write error: %d %d\n",
                            _tsp_state_to_string(state->state), sub_res,
                            res_ex);
                        state->state = TSP_STATE_NEED_CLOSE;
                        break;
                    } else {
                        LOG(LEVEL_DETAIL,
                            "(TSP Parse RESPONSE: %s) SSL_write: %d\n",
                            _tsp_state_to_string(state->state), sub_res);
                        size_t sub_offset = 0;
                        while (true) {
                            if (tls_state->data_size - sub_offset <= 0) {
                                _extend_buffer(&tls_state->data,
                                               &tls_state->data_size);
                            }

                            sub_res = BIO_read(
                                tls_state->wbio, tls_state->data + sub_offset,
                                (unsigned int)(tls_state->data_size -
                                               sub_offset));
                            if (sub_res > 0) {
                                LOG(LEVEL_DETAIL,
                                    "(TSP Parse RESPONSE: %s) BIO_read: %d\n",
                                    _tsp_state_to_string(state->state),
                                    sub_res);
                                sub_offset += (size_t)sub_res;
                            } else if (sub_res == 0 || sub_res == -1) {
                                LOG(LEVEL_DEBUG,
                                    "(TSP Parse RESPONSE: %s) BIO_read: %d\n",
                                    _tsp_state_to_string(state->state),
                                    sub_res);
                                break;
                            } else {
                                LOG(LEVEL_WARN,
                                    "(TSP Parse RESPONSE: %s) BIO_read failed: "
                                    "%d\n",
                                    _tsp_state_to_string(state->state),
                                    sub_res);
                                state->state = TSP_STATE_NEED_CLOSE;
                                break;
                            }
                        }
                        if (state->state != TSP_STATE_NEED_CLOSE) {
                            datapass_set_data(pass, tls_state->data, sub_offset,
                                              true);
                            pass->is_close = subpass.is_close;
                            state->state   = TSP_STATE_RECV_DATA;
                            is_continue    = false;
                            break;
                        }
                    }
                } else {
                    res_ex = SSL_get_error(tls_state->ssl, res);
                    if (res_ex == SSL_ERROR_WANT_READ) {
                        /**
                         * No data because SSL record is incomplete.
                         * Go on to wait further data.
                         * */
                        is_continue = false;
                    } else if (res_ex == SSL_ERROR_ZERO_RETURN) {
                        state->state = TSP_STATE_NEED_CLOSE;
                    } else {
                        if (res_ex != SSL_ERROR_SSL) {
                            LOG(LEVEL_WARN,
                                "(TSP Parse RESPONSE: %s) SSL_read error: %d "
                                "%d\n",
                                _tsp_state_to_string(state->state), res,
                                res_ex);
                            LOGopenssl(LEVEL_WARN);
                        }
                        state->state = TSP_STATE_NEED_CLOSE;
                    }
                }
                break;
            }

            case TSP_STATE_NEED_CLOSE:
                pass->is_close = 1;
                pass->len      = 0;
                pass->data     = NULL;
                is_continue    = false;
                break;
        }
    }

    return ret;
}

Probe TlsStateProbe = {
    .name       = "tls-state",
    .type       = ProbeType_STATE,
    .multi_mode = Multi_Null,
    .multi_num  = 1,
    .hello_wait = 0,
    .params     = tlsstate_parameters,
    .short_desc = "Do TLS upper-layer scan with specified probe.",
    .desc =
        "TlsState Probe emulates SSL/TLS layer by OpenSSL BIO machanism. "
        "It is used with TcpState ScanModule to perform TLS probing based on "
        "our user-spase TCP stack. TlsState is just a middle layer(probe), so "
        "we should specify a subprobe for it.\n"
        "NOTE1: TlsState doesn't support initial waiting before hello for "
        "subprobe because the nesting.\n"
        "NOTE2: TlsState probe is designed to be compatible with wide range of "
        "servers in version of TLS from v1.0 to v1.3. So our settings of "
        "OpenSSL is not safe from the modern perspective.\n"
        "NOTE3: The quote symbol in nested parameter can be a problem while we "
        "use `subprobearg` for beginners. I give you a complete command as a "
        "simple example here:\n"
        "```\n"
        "    xtate -scan tcp-state -probe tls-state -probearg \"-subprobe "
        "hello-state -subprobearg '-nmap \\'GET / HTTP/1.0\\r\\n\\r\\n\\'' "
        "-version -subject\" -ip 192.168.0.1 -p 443 -rate 500 -wait 30\n"
        "```\n"
        "Dependencies: OpenSSL.",

    .init_cb           = &tlsstate_init,
    .conn_init_cb      = &tlsstate_conn_init,
    .make_hello_cb     = &tlsstate_make_hello,
    .parse_response_cb = &tlsstate_parse_response,
    .conn_close_cb     = &tlsstate_conn_close,
    .close_cb          = &tlsstate_close,
};

#endif