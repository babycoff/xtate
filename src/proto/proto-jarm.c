#ifndef NOT_FOUND_OPENSSL

#include "proto-jarm.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "proto-tls.h"
#include "../util-misc/misc.h"
#include "../util-data/safe-string.h"
#include "../util-data/data-convert.h"

static const char *JarmCipherSuitesAll[] = {
    "\x00\x16", "\x00\x33", "\x00\x67", "\xc0\x9e", "\xc0\xa2", "\x00\x9e",
    "\x00\x39", "\x00\x6b", "\xc0\x9f", "\xc0\xa3", "\x00\x9f", "\x00\x45",
    "\x00\xbe", "\x00\x88", "\x00\xc4", "\x00\x9a", "\xc0\x08", "\xc0\x09",
    "\xc0\x23", "\xc0\xac", "\xc0\xae", "\xc0\x2b", "\xc0\x0a", "\xc0\x24",
    "\xc0\xad", "\xc0\xaf", "\xc0\x2c", "\xc0\x72", "\xc0\x73", "\xcc\xa9",
    "\x13\x02", "\x13\x01", "\xcc\x14", "\xc0\x07", "\xc0\x12", "\xc0\x13",
    "\xc0\x27", "\xc0\x2f", "\xc0\x14", "\xc0\x28", "\xc0\x30", "\xc0\x60",
    "\xc0\x61", "\xc0\x76", "\xc0\x77", "\xcc\xa8", "\x13\x05", "\x13\x04",
    "\x13\x03", "\xcc\x13", "\xc0\x11", "\x00\x0a", "\x00\x2f", "\x00\x3c",
    "\xc0\x9c", "\xc0\xa0", "\x00\x9c", "\x00\x35", "\x00\x3d", "\xc0\x9d",
    "\xc0\xa1", "\x00\x9d", "\x00\x41", "\x00\xba", "\x00\x84", "\x00\xc0",
    "\x00\x07", "\x00\x04", "\x00\x05",
};

static const char *JarmCipherSuites_Without_1_3[] = {
    "\x00\x16", "\x00\x33", "\x00\x67", "\xc0\x9e", "\xc0\xa2", "\x00\x9e",
    "\x00\x39", "\x00\x6b", "\xc0\x9f", "\xc0\xa3", "\x00\x9f", "\x00\x45",
    "\x00\xbe", "\x00\x88", "\x00\xc4", "\x00\x9a", "\xc0\x08", "\xc0\x09",
    "\xc0\x23", "\xc0\xac", "\xc0\xae", "\xc0\x2b", "\xc0\x0a", "\xc0\x24",
    "\xc0\xad", "\xc0\xaf", "\xc0\x2c", "\xc0\x72", "\xc0\x73", "\xcc\xa9",
    "\xcc\x14", "\xc0\x07", "\xc0\x12", "\xc0\x13", "\xc0\x27", "\xc0\x2f",
    "\xc0\x14", "\xc0\x28", "\xc0\x30", "\xc0\x60", "\xc0\x61", "\xc0\x76",
    "\xc0\x77", "\xcc\xa8", "\xcc\x13", "\xc0\x11", "\x00\x0a", "\x00\x2f",
    "\x00\x3c", "\xc0\x9c", "\xc0\xa0", "\x00\x9c", "\x00\x35", "\x00\x3d",
    "\xc0\x9d", "\xc0\xa1", "\x00\x9d", "\x00\x41", "\x00\xba", "\x00\x84",
    "\x00\xc0", "\x00\x07", "\x00\x04", "\x00\x05",
};

/*som static Jarm defined tls extension value*/
#define JARM_EXT_EXTENDED_MASTER_SECRET "\x00\x00"
#define JARM_EXT_MAX_FRAGMENT_LENGTH    "\x00\x01\x01"
#define JARM_EXT_RENEGOTIATION_INFO     "\x00\x01\x00"
#define JARM_EXT_SUPPORTED_GROUPS                                              \
    "\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
#define JARM_EXT_EC_POINT_FORMATS "\x00\x02\x01\x00"
#define JARM_EXT_SESSION_TICKET   "\x00\x00"
#define JARM_EXT_SIGNATURE_ALGORITHMS                                          \
    "\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06" \
    "\x06\x01\x02\x01"
#define JARM_EXT_PSK_KEY_EXCHANGE_MODES "\x00\x02\x01\x01"

static const char *JarmAlpnForwardList[] = {
    TLS_EXT_ALPN_PROTO_HTTP_0_9,
    TLS_EXT_ALPN_PROTO_HTTP_1_0,
    TLS_EXT_ALPN_PROTO_HTTP_1_1,
    TLS_EXT_ALPN_PROTO_SPDY_1,
    TLS_EXT_ALPN_PROTO_SPDY_2,
    TLS_EXT_ALPN_PROTO_SPDY_3,
    TLS_EXT_ALPN_PROTO_HTTP_2_OVER_TLS,
    TLS_EXT_ALPN_PROTO_HTTP_2_OVER_CLEARTEXT,
    TLS_EXT_ALPN_PROTO_HTTP_QUIC,
};

static const char *JarmAlpnReverseList[] = {
    TLS_EXT_ALPN_PROTO_HTTP_QUIC,
    TLS_EXT_ALPN_PROTO_HTTP_2_OVER_CLEARTEXT,
    TLS_EXT_ALPN_PROTO_HTTP_2_OVER_TLS,
    TLS_EXT_ALPN_PROTO_SPDY_3,
    TLS_EXT_ALPN_PROTO_SPDY_2,
    TLS_EXT_ALPN_PROTO_SPDY_1,
    TLS_EXT_ALPN_PROTO_HTTP_1_1,
    TLS_EXT_ALPN_PROTO_HTTP_1_0,
    TLS_EXT_ALPN_PROTO_HTTP_0_9,
};

static const char *JarmAlpnForwardListRare[] = {
    TLS_EXT_ALPN_PROTO_HTTP_0_9,  TLS_EXT_ALPN_PROTO_HTTP_1_0,
    TLS_EXT_ALPN_PROTO_SPDY_1,    TLS_EXT_ALPN_PROTO_SPDY_2,
    TLS_EXT_ALPN_PROTO_SPDY_3,    TLS_EXT_ALPN_PROTO_HTTP_2_OVER_CLEARTEXT,
    TLS_EXT_ALPN_PROTO_HTTP_QUIC,
};

static const char *JarmAlpnReverseListRare[] = {
    TLS_EXT_ALPN_PROTO_HTTP_QUIC, TLS_EXT_ALPN_PROTO_HTTP_2_OVER_CLEARTEXT,
    TLS_EXT_ALPN_PROTO_SPDY_3,    TLS_EXT_ALPN_PROTO_SPDY_2,
    TLS_EXT_ALPN_PROTO_SPDY_1,    TLS_EXT_ALPN_PROTO_HTTP_1_0,
    TLS_EXT_ALPN_PROTO_HTTP_0_9,
};

static const uint16_t JarmSupportedVersionList_1_2_FORWORD[] = {
    TLS1_VERSION,
    TLS1_1_VERSION,
    TLS1_2_VERSION,
};

static const uint16_t JarmSupportedVersionList_1_2_REVERSE[] = {
    TLS1_2_VERSION,
    TLS1_1_VERSION,
    TLS1_VERSION,
};

static const uint16_t JarmSupportedVersionList_1_3_FORWARD[] = {
    TLS1_VERSION,
    TLS1_1_VERSION,
    TLS1_2_VERSION,
    TLS1_3_VERSION,
};

static const uint16_t JarmSupportedVersionList_1_3_REVERSE[] = {
    TLS1_3_VERSION,
    TLS1_2_VERSION,
    TLS1_1_VERSION,
    TLS1_VERSION,
};

static size_t jarm_load_ext_supported_versions(struct JarmConfig *jc,
                                               unsigned char     *px) {
    size_t r_len = 0;

    /*extension type*/
    U16_TO_BE(px, TLSEXT_TYPE_supported_versions);
    r_len += 2;

    unsigned char *ver_start = px + 5;

    if (jc->grease_use == GreaseUse_YES) {
        uint16_t grease;
        grease = tls_get_a_grease(rand());
        U16_TO_BE(ver_start, grease);
        ver_start += 2;
        r_len += 2;
    }

    if (jc->support_ver_ext == SupportVerExt_1_2_SUPPORT &&
        jc->ext_order == ExtOrder_FORWARD) {
        for (unsigned i = 0;
             i < ARRAY_SIZE(JarmSupportedVersionList_1_2_FORWORD); i++) {
            ver_start[0] = JarmSupportedVersionList_1_2_FORWORD[i] >> 8 & 0xFF;
            ver_start[1] = JarmSupportedVersionList_1_2_FORWORD[i] >> 0 & 0xFF;
            ver_start += 2;
            r_len += 2;
        }
    } else if (jc->support_ver_ext == SupportVerExt_1_2_SUPPORT &&
               jc->ext_order == ExtOrder_REVERSE) {
        for (unsigned i = 0;
             i < ARRAY_SIZE(JarmSupportedVersionList_1_2_REVERSE); i++) {
            ver_start[0] = JarmSupportedVersionList_1_2_REVERSE[i] >> 8 & 0xFF;
            ver_start[1] = JarmSupportedVersionList_1_2_REVERSE[i] >> 0 & 0xFF;
            ver_start += 2;
            r_len += 2;
        }
    } else if (jc->support_ver_ext == SupportVerExt_1_3_SUPPORT &&
               jc->ext_order == ExtOrder_FORWARD) {
        for (unsigned i = 0;
             i < ARRAY_SIZE(JarmSupportedVersionList_1_3_FORWARD); i++) {
            ver_start[0] = JarmSupportedVersionList_1_3_FORWARD[i] >> 8 & 0xFF;
            ver_start[1] = JarmSupportedVersionList_1_3_FORWARD[i] >> 0 & 0xFF;
            ver_start += 2;
            r_len += 2;
        }
    } else if (jc->support_ver_ext == SupportVerExt_1_3_SUPPORT &&
               jc->ext_order == ExtOrder_REVERSE) {
        for (unsigned i = 0;
             i < ARRAY_SIZE(JarmSupportedVersionList_1_3_REVERSE); i++) {
            ver_start[0] = JarmSupportedVersionList_1_3_REVERSE[i] >> 8 & 0xFF;
            ver_start[1] = JarmSupportedVersionList_1_3_REVERSE[i] >> 0 & 0xFF;
            ver_start += 2;
            r_len += 2;
        }
    }

    /*supported version length*/
    uint8_t sv_len;
    sv_len = ver_start - (px + 5);
    px[4]  = sv_len;
    r_len += 1;
    /*extension length*/
    uint16_t ext_len;
    ext_len = sv_len + 1;
    U16_TO_BE(px + 2, ext_len);
    r_len += 2;

    return r_len;
}

static size_t jarm_load_ext_key_share(struct JarmConfig *jc,
                                      unsigned char     *px) {
    size_t         r_len  = 0;
    unsigned char *ks_ext = px + 6;

    /*extension type*/
    U16_TO_BE(px, TLSEXT_TYPE_key_share);
    r_len += 2;

    /*jarm insert grease to head in key share extension*/
    if (jc->grease_use == GreaseUse_YES) {
        /*Group: GREASE*/
        uint16_t grease;
        grease = tls_get_a_grease(rand());
        U16_TO_BE(ks_ext, grease);
        /*Key Exchange Length & Key Exchange*/
        memcpy(ks_ext + 2, "\x00\x01\x00", sizeof("\x00\x01\x00") - 1);
        ks_ext += 5;
        r_len += 5;
    }

    /*Group*/
    memcpy(ks_ext, TLS_EXT_KEY_SHARE_GROUP_X25519,
           sizeof(TLS_EXT_KEY_SHARE_GROUP_X25519) - 1);
    ks_ext += (sizeof(TLS_EXT_KEY_SHARE_GROUP_X25519) - 1);
    r_len += (sizeof(TLS_EXT_KEY_SHARE_GROUP_X25519) - 1);
    /*Key Exchange Length: 32*/
    memcpy(ks_ext, "\x00\x20", sizeof("\x00\x20") - 1);
    ks_ext += (sizeof("\x00\x20") - 1);
    r_len += (sizeof("\x00\x20") - 1);
    /*32 bytes random value as Key Exchange*/
    for (unsigned i = 0; i < 32 / 4; i++) {
        int r = rand();
        U32_TO_BE(ks_ext, r);
        ks_ext += 4;
        r_len += 4;
    }
    /*client key share length*/
    uint16_t cks_len = ks_ext - (px + 6);
    U16_TO_BE(px + 4, cks_len);
    r_len += 2;
    /*key share extension length*/
    uint16_t ext_len = cks_len + 2;
    U16_TO_BE(px + 2, ext_len);
    r_len += 2;

    return r_len;
}

/**
 * @param jc config of jarm.
 * @param px put raw extensions with length in px.
 * @return length of extensions data (with length).
 */
static size_t jarm_load_extensions(struct JarmConfig *jc, unsigned char *px) {
    unsigned char *ext_start = px + 2;
    size_t         tmp_len;

    /*
     * Jarm always inserts grease to head for extensions.
     * And many browsers too.
     */
    if (jc->grease_use == GreaseUse_YES) {
        uint16_t grease;
        grease = tls_get_a_grease(rand());
        U16_TO_BE(ext_start, grease);
        ext_start[2] = 0;
        ext_start[3] = 0;
        ext_start += 4;
    }

    /*
     *Load Extensions one by one
     */

    /*
     * According to RFC6066, SNI extension is not permitted to use IP addr,
     * But Jarm uses IP addr and I havn't found some problem in fingerprinting
     * yet.
     */
    tmp_len = tls_load_ext_sni(ext_start, jc->servername);
    ext_start += tmp_len;

    U16_TO_BE(ext_start, TLSEXT_TYPE_extended_master_secret);
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_EXTENDED_MASTER_SECRET,
           sizeof(JARM_EXT_EXTENDED_MASTER_SECRET) - 1);
    ext_start += (sizeof(JARM_EXT_EXTENDED_MASTER_SECRET) - 1);

    ext_start[0] = TLSEXT_TYPE_max_fragment_length >> 8 & 0xFF;
    ext_start[1] = TLSEXT_TYPE_max_fragment_length >> 0 & 0xFF;
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_MAX_FRAGMENT_LENGTH,
           sizeof(JARM_EXT_MAX_FRAGMENT_LENGTH) - 1);
    ext_start += (sizeof(JARM_EXT_MAX_FRAGMENT_LENGTH) - 1);

    U16_TO_BE(ext_start, TLSEXT_TYPE_renegotiate);
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_RENEGOTIATION_INFO,
           sizeof(JARM_EXT_RENEGOTIATION_INFO) - 1);
    ext_start += (sizeof(JARM_EXT_RENEGOTIATION_INFO) - 1);

    U16_TO_BE(ext_start, TLSEXT_TYPE_supported_groups);
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_SUPPORTED_GROUPS,
           sizeof(JARM_EXT_SUPPORTED_GROUPS) - 1);
    ext_start += (sizeof(JARM_EXT_SUPPORTED_GROUPS) - 1);

    U16_TO_BE(ext_start, TLSEXT_TYPE_ec_point_formats);
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_EC_POINT_FORMATS,
           sizeof(JARM_EXT_EC_POINT_FORMATS) - 1);
    ext_start += (sizeof(JARM_EXT_EC_POINT_FORMATS) - 1);

    U16_TO_BE(ext_start, TLSEXT_TYPE_session_ticket);
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_SESSION_TICKET,
           sizeof(JARM_EXT_SESSION_TICKET) - 1);
    ext_start += (sizeof(JARM_EXT_SESSION_TICKET) - 1);

    if (jc->ext_order == ExtOrder_FORWARD && jc->alpn_use == AlpnUse_ALL) {
        tmp_len = tls_load_ext_alpn(ext_start, JarmAlpnForwardList,
                                    ARRAY_SIZE(JarmAlpnForwardList));
    } else if (jc->ext_order == ExtOrder_REVERSE &&
               jc->alpn_use == AlpnUse_ALL) {
        tmp_len = tls_load_ext_alpn(ext_start, JarmAlpnReverseList,
                                    ARRAY_SIZE(JarmAlpnReverseList));
    } else if (jc->ext_order == ExtOrder_FORWARD &&
               jc->alpn_use == AlpnUse_RARE) {
        tmp_len = tls_load_ext_alpn(ext_start, JarmAlpnForwardListRare,
                                    ARRAY_SIZE(JarmAlpnForwardListRare));
    } else if (jc->ext_order == ExtOrder_REVERSE &&
               jc->alpn_use == AlpnUse_RARE) {
        tmp_len = tls_load_ext_alpn(ext_start, JarmAlpnReverseListRare,
                                    ARRAY_SIZE(JarmAlpnReverseListRare));
    }
    ext_start += tmp_len;

    U16_TO_BE(ext_start, TLSEXT_TYPE_signature_algorithms);
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_SIGNATURE_ALGORITHMS,
           sizeof(JARM_EXT_SIGNATURE_ALGORITHMS) - 1);
    ext_start += (sizeof(JARM_EXT_SIGNATURE_ALGORITHMS) - 1);

    tmp_len = jarm_load_ext_key_share(jc, ext_start);
    ext_start += tmp_len;

    U16_TO_BE(ext_start, TLSEXT_TYPE_psk_kex_modes);
    ext_start += 2;
    memcpy(ext_start, JARM_EXT_PSK_KEY_EXCHANGE_MODES,
           sizeof(JARM_EXT_PSK_KEY_EXCHANGE_MODES) - 1);
    ext_start += (sizeof(JARM_EXT_PSK_KEY_EXCHANGE_MODES) - 1);

    if (jc->support_ver_ext != SupportVerExt_NO_SUPPORT) {
        tmp_len = jarm_load_ext_supported_versions(jc, ext_start);
        ext_start += tmp_len;
    }

    /*all extension length*/
    uint16_t ext_len;
    ext_len = ext_start - (px + 2);
    U16_TO_BE(px, ext_len);

    return (size_t)(ext_start - px);
}

/**
 * Adjust the cipher list according to JarmCipherOrder
 * @param jc config of jarm.
 * @param px put raw cipher data in px.
 * @param list cipher list like JarmCipherSuitesAll.
 * @param count num of cipher suites in list.
 * @return length of cipher data
 */
static size_t jarm_cipherlist_mung(struct JarmConfig *jc, unsigned char *px,
                                   const char **list, unsigned count) {
    size_t r_len = 0;

    /*
     * Jarm always inserts grease to head for ciphersuites.
     * And many browsers too.
     */
    if (jc->grease_use == GreaseUse_YES) {
        uint16_t grease;
        grease = tls_get_a_grease(rand());
        U16_TO_BE(px, grease);
        px += 2;
        r_len += 2;
    }

    unsigned half_count;

    if (jc->cipher_order == CipherOrder_FORWARD) {
        for (unsigned i = 0; i < count; i++) {
            px[i * 2 + 0] = list[i][0];
            px[i * 2 + 1] = list[i][1];
        }
        r_len += count * 2;
    } else if (jc->cipher_order == CipherOrder_REVERSE) {
        for (unsigned i = 0; i < count; i++) {
            px[i * 2 + 0] = list[count - i - 1][0];
            px[i * 2 + 1] = list[count - i - 1][1];
        }
        r_len += count * 2;
    } else if (jc->cipher_order == CipherOrder_BOTTOM_HALF) {
        /*bottom_half doesn't contain middle*/
        if (count % 2 == 1)
            half_count = count / 2 + 1;
        else
            half_count = count / 2;
        for (unsigned i = half_count; i < count; i++) {
            px[(i - half_count) * 2 + 0] = list[i][0];
            px[(i - half_count) * 2 + 1] = list[i][1];
        }
        r_len += (count - half_count) * 2;
    } else if (jc->cipher_order == CipherOrder_TOP_HALF) {
        /*top_half contains middle*/
        if (count % 2 == 1)
            half_count = count / 2 + 1;
        else
            half_count = count / 2;
        for (unsigned i = 0; i < half_count; i++) {
            px[i * 2 + 0] = list[half_count - 1 - i][0];
            px[i * 2 + 1] = list[half_count - 1 - i][1];
        }
        r_len += half_count * 2;
    } else if (jc->cipher_order == CipherOrder_MIDDLE_OUT) {
        /*from middle to both edge*/
        half_count = count / 2;
        /*start with middle if uneven*/
        if (count % 2 == 1) {
            px[0] = list[half_count][0];
            px[1] = list[half_count][1];
            px += 2;

            for (unsigned i = 0; i < half_count; i++) {
                px[i * 4 + 0] = list[half_count + 1 + i][0];
                px[i * 4 + 1] = list[half_count + 1 + i][1];
                px[i * 4 + 2] = list[half_count - 1 - i][0];
                px[i * 4 + 3] = list[half_count - 1 - i][1];
            }
        }
        /*even*/
        else {
            for (unsigned i = 0; i < half_count; i++) {
                px[i * 4 + 0] = list[half_count + i][0];
                px[i * 4 + 1] = list[half_count + i][1];
                px[i * 4 + 2] = list[half_count - 1 - i][0];
                px[i * 4 + 4] = list[half_count - 1 - i][1];
            }
        }

        r_len += count * 2;
    }

    return r_len;
}

/**
 * @param jc config of jarm.
 * @param px put raw cipher data with length in px.
 * @return length of cipher data (with length).
 */
static size_t jarm_load_cipherlist(struct JarmConfig *jc, unsigned char *px) {
    const char **cs_list;
    unsigned     cs_count;
    size_t       r_len;

    if (jc->cipher_list == CipherList_ALL) {
        cs_list  = JarmCipherSuitesAll;
        cs_count = ARRAY_SIZE(JarmCipherSuitesAll);
    } else {
        cs_list  = JarmCipherSuites_Without_1_3;
        cs_count = ARRAY_SIZE(JarmCipherSuites_Without_1_3);
    }

    /*load raw cipher suites list*/
    r_len = jarm_cipherlist_mung(jc, px + 2, cs_list, cs_count);
    /*fill Length of cipher suites*/
    U16_TO_BE(px, r_len);

    /*total length*/
    return r_len + 2;
}

size_t jarm_create_ch(struct JarmConfig *jc, unsigned char *buf,
                      unsigned buf_len) {
    unsigned char
           px[TLS_CLIENTHELLO_MAX_LEN]; /*clienthello with record header*/
    size_t tmp_len;

    /*for random*/
    unsigned r;
    srand((unsigned)time(NULL));

    /*Content Type: Handshake*/
    px[0] = TLS_RECORD_CONTENT_TYPE_HANDSHAKE;

    /*Version about*/
    if (jc->version == SSL3_VERSION) {
        /*Version in Record layer header*/
        U16_TO_BE(px + 1, SSL3_VERSION);
        /*Version in Handshake protocol*/
        U16_TO_BE(px + 9, SSL3_VERSION);
    } else if (jc->version == TLS1_VERSION) {
        U16_TO_BE(px + 1, TLS1_VERSION);
        U16_TO_BE(px + 9, TLS1_VERSION);
    } else if (jc->version == TLS1_1_VERSION) {
        U16_TO_BE(px + 1, TLS1_1_VERSION);
        U16_TO_BE(px + 9, TLS1_1_VERSION);
    } else if (jc->version == TLS1_2_VERSION) {
        U16_TO_BE(px + 1, TLS1_2_VERSION);
        U16_TO_BE(px + 9, TLS1_2_VERSION);
    } else if (jc->version == TLS1_3_VERSION) {
        U16_TO_BE(px + 1, TLS1_VERSION);
        U16_TO_BE(px + 9, TLS1_2_VERSION);
    }

    /*handshake type: clienthello*/
    px[5] = TLS_HANDSHAKE_TYPE_CLIENTHELLO;

    /*p points to fields we are filling*/
    unsigned char *p = px + 11; /*Now it's Random in Handshake Protocol*/

    /*32 bytes of Random*/
    for (unsigned i = 0; i < 32 / 4; i++) {
        r = rand();
        U32_TO_BE(p, r);
        p += 4;
    }

    /*Session ID Length*/
    p[0] = 0x20;
    p++;
    /*32 bytes of Session ID*/
    for (unsigned i = 0; i < 32 / 4; i++) {
        r = rand();
        U32_TO_BE(p, r);
        p += 4;
    }

    /*Cipher Suites*/
    tmp_len = jarm_load_cipherlist(jc, p);
    p += tmp_len;

    /*Compression Method*/
    p[0] = 0x01; /*Length*/
    p[1] = 0x00; /*Method*/
    p += 2;

    /*Extensions*/
    tmp_len = jarm_load_extensions(jc, p);
    p += tmp_len;

    /*set inner length*/
    uint16_t in_len;
    in_len = p - (px + 9);
    px[6]  = 0x00;
    U16_TO_BE(px + 7, in_len);
    /*set outter length*/
    uint16_t out_len;
    out_len = in_len + 4;
    U16_TO_BE(px + 3, out_len);

    size_t r_len = p - px;
    if ((unsigned)r_len > buf_len) {
        return 0;
    } else {
        memcpy(buf, px, r_len);
        return r_len;
    }
}

static size_t extract_ext(const unsigned char *payload, size_t payload_len,
                          char *res_buf, size_t res_max) {
#define CHECK_IDX(idx)                                                         \
    if ((idx) >= (payload_len))                                                \
        return snprintf(res_buf, res_max, "|");

    CHECK_IDX(43 + 2)

    size_t   res_len = 0;
    unsigned counter = payload[43];
    CHECK_IDX(counter + 49)
    unsigned count   = counter + 49;
    unsigned sh_len  = BE_TO_U16(payload + 3);
    unsigned length  = BE_TO_U16(payload + counter + 47);
    unsigned maximum = length + (count - 1);

    if (payload[counter + 47] == 11)
        return snprintf(res_buf, res_max, "|");
    else if ((payload_len > counter + 52 &&
              safe_bytes_equals(payload + counter + 50, 3, "\x0e\xac\x0b",
                                3) > 0) ||
             (payload_len > 84 &&
              safe_bytes_equals(payload + 82, 3, "\x0f\xf0\x0b", 3) > 0))
        return snprintf(res_buf, res_max, "|");
    else if (counter + 42 >= sh_len)
        return snprintf(res_buf, res_max, "|");

    unsigned char *type;
    unsigned       ext_length;

    /* to get alpn selection*/
    while (count < maximum) {
        CHECK_IDX(count + 2 + 2)

        type       = (unsigned char *)payload + count;
        ext_length = BE_TO_U16(payload + count + 2);

        if (ext_length == 0) {
            count += 4;
        } else {
            CHECK_IDX(count + 4 + ext_length)

            if (safe_bytes_equals(type, 2, "\x00\x10", 2)) {
                memcpy(res_buf + res_len, payload + count + 4 + 3,
                       ext_length - 3);
                res_len += (ext_length - 3);
            }

            count += (ext_length + 4);
        }
    }

    res_buf[res_len] = '|';
    res_len++;

    count = counter + 49;
    /* to get formating hyphens*/
    while (count < maximum) {
        CHECK_IDX(count + 2 + 2)

        type       = (unsigned char *)payload + count;
        ext_length = BE_TO_U16(payload + count + 2);

        res_len += snprintf(res_buf + res_len, res_max - res_len, "%02x%02x",
                            type[0], type[1]);

        res_buf[res_len] = '-';
        res_len++;

        if (ext_length == 0) {
            count += 4;
        } else {
            count += (ext_length + 4);
        }
    }

    res_buf[res_len - 1] = '\0';
    res_len--;

    return res_len;

#undef CHECK_IDX
}

size_t jarm_decipher_one(const unsigned char *payload, size_t payload_len,
                         char *res_buf, size_t res_max) {
#define CHECK_IDX(idx)                                                         \
    if ((idx) >= (payload_len))                                                \
        return snprintf(res_buf, res_max, "|||");

    size_t res_len = 0;

    CHECK_IDX(5)

    if (payload[0] == 22 && payload[5] == 2) {
        CHECK_IDX(43)

        unsigned counter = payload[43];

        CHECK_IDX(counter + 45)

        /*Selected cipher*/
        res_len += snprintf(res_buf + res_len, res_max - res_len, "%02x%02x|",
                            payload[counter + 44], payload[counter + 45]);
        /*Version info*/
        res_len += snprintf(res_buf + res_len, res_max - res_len, "%02x%02x|",
                            payload[9], payload[10]);
        /*Extract extensions*/
        res_len += extract_ext(payload, payload_len, res_buf + res_len,
                               res_max - res_len);

        return res_len;
    }

    return snprintf(res_buf, res_max, "|||");

#undef CHECK_IDX
}

#endif /*ifndef NOT_FOUND_OPENSSL*/