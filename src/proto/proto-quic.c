#ifndef NOT_FOUND_OPENSSL

#include "proto-quic.h"

#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "../util-data/safe-string.h"

#define QUIC_V1 0x00000001u
#define QUIC_HASH_LEN 32
#define QUIC_KEY_LEN 16
#define QUIC_IV_LEN 12
#define QUIC_HP_LEN 16
#define QUIC_TAG_LEN 16
#define QUIC_PN_LEN 2

static const uint8_t quic_v1_salt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

static size_t varint_len(uint64_t v) {
    if (v < 64)
        return 1;
    if (v < 16384)
        return 2;
    if (v < 1073741824ULL)
        return 4;
    return 8;
}

static int put_varint(uint8_t *buf, size_t cap, size_t *off, uint64_t v) {
    size_t n = varint_len(v);
    if (*off + n > cap)
        return 0;
    if (n == 1) {
        buf[(*off)++] = (uint8_t)v;
    } else if (n == 2) {
        buf[(*off)++] = (uint8_t)(0x40 | (v >> 8));
        buf[(*off)++] = (uint8_t)v;
    } else if (n == 4) {
        buf[(*off)++] = (uint8_t)(0x80 | (v >> 24));
        buf[(*off)++] = (uint8_t)(v >> 16);
        buf[(*off)++] = (uint8_t)(v >> 8);
        buf[(*off)++] = (uint8_t)v;
    } else {
        buf[(*off)++] = (uint8_t)(0xC0 | (v >> 56));
        for (int i = 5; i >= 0; i--)
            buf[(*off)++] = (uint8_t)(v >> (i * 8));
    }
    return 1;
}

static int get_varint(const uint8_t *buf, size_t len, size_t *off, uint64_t *v) {
    if (*off >= len)
        return 0;
    uint8_t first = buf[*off];
    size_t  n     = (size_t)1 << (first >> 6);
    if (*off + n > len)
        return 0;
    uint64_t value = first & 0x3F;
    for (size_t i = 1; i < n; i++)
        value = (value << 8) | buf[*off + i];
    *off += n;
    *v = value;
    return 1;
}

static int append_bytes(uint8_t *buf, size_t cap, size_t *off, const void *src,
                        size_t len) {
    if (*off + len > cap)
        return 0;
    memcpy(buf + *off, src, len);
    *off += len;
    return 1;
}

static int append_u8(uint8_t *buf, size_t cap, size_t *off, uint8_t v) {
    return append_bytes(buf, cap, off, &v, 1);
}

static int append_u16(uint8_t *buf, size_t cap, size_t *off, uint16_t v) {
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    return append_bytes(buf, cap, off, b, 2);
}

static int append_u24(uint8_t *buf, size_t cap, size_t *off, uint32_t v) {
    uint8_t b[3] = {(uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    return append_bytes(buf, cap, off, b, 3);
}

static uint32_t get_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                       size_t data_len, uint8_t out[QUIC_HASH_LEN]) {
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len))
        return 0;
    return out_len == QUIC_HASH_LEN;
}

static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t out[QUIC_HASH_LEN]) {
    return hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

static int hkdf_expand(const uint8_t *prk, const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    uint8_t t[QUIC_HASH_LEN];
    size_t  t_len = 0;
    size_t  done  = 0;
    uint8_t counter = 1;

    while (done < out_len) {
        uint8_t input[256];
        size_t  input_len = 0;
        if (t_len + info_len + 1 > sizeof(input))
            return 0;
        if (t_len)
            memcpy(input + input_len, t, t_len), input_len += t_len;
        if (info_len)
            memcpy(input + input_len, info, info_len), input_len += info_len;
        input[input_len++] = counter++;
        if (!hmac_sha256(prk, QUIC_HASH_LEN, input, input_len, t))
            return 0;
        t_len = QUIC_HASH_LEN;
        size_t n = out_len - done < QUIC_HASH_LEN ? out_len - done
                                                   : QUIC_HASH_LEN;
        memcpy(out + done, t, n);
        done += n;
    }
    return 1;
}

static int hkdf_expand_label(const uint8_t secret[QUIC_HASH_LEN],
                             const char *label, uint8_t *out, size_t out_len) {
    uint8_t info[128];
    size_t  off = 0;
    size_t  label_len = strlen(label);
    if (label_len + 6 > 255)
        return 0;
    if (label_len + 6 > 255 || out_len > 65535)
        return 0;
    if (!append_u16(info, sizeof(info), &off, (uint16_t)out_len) ||
        !append_u8(info, sizeof(info), &off, (uint8_t)(6 + label_len)) ||
        !append_bytes(info, sizeof(info), &off, "tls13 ", 6) ||
        !append_bytes(info, sizeof(info), &off, label, label_len) ||
        !append_u8(info, sizeof(info), &off, 0))
        return 0;
    return hkdf_expand(secret, info, off, out, out_len);
}

static int derive_client_initial(const uint8_t *dcid, size_t dcid_len,
                                 uint8_t key[QUIC_KEY_LEN],
                                 uint8_t iv[QUIC_IV_LEN],
                                 uint8_t hp[QUIC_HP_LEN]) {
    uint8_t initial_secret[QUIC_HASH_LEN];
    uint8_t client_secret[QUIC_HASH_LEN];
    if (!hkdf_extract(quic_v1_salt, sizeof(quic_v1_salt), dcid, dcid_len,
                      initial_secret))
        return 0;
    if (!hkdf_expand_label(initial_secret, "client in", client_secret,
                           sizeof(client_secret)))
        return 0;
    if (!hkdf_expand_label(client_secret, "quic key", key, QUIC_KEY_LEN))
        return 0;
    if (!hkdf_expand_label(client_secret, "quic iv", iv, QUIC_IV_LEN))
        return 0;
    if (!hkdf_expand_label(client_secret, "quic hp", hp, QUIC_HP_LEN))
        return 0;
    return 1;
}

static int aes_gcm_encrypt(const uint8_t key[QUIC_KEY_LEN],
                           const uint8_t iv[QUIC_IV_LEN], const uint8_t *aad,
                           size_t aad_len, const uint8_t *plain,
                           size_t plain_len, uint8_t *cipher,
                           uint8_t tag[QUIC_TAG_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;
    int len = 0;
    int ok  = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QUIC_IV_LEN, NULL) !=
        1)
        goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len) != 1)
        goto out;
    int total = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + total, &len) != 1)
        goto out;
    total += len;
    if ((size_t)total != plain_len)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, QUIC_TAG_LEN, tag) != 1)
        goto out;
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aes_ecb_mask(const uint8_t hp[QUIC_HP_LEN], const uint8_t *sample,
                        uint8_t mask[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;
    int len = 0;
    int ok  = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp, NULL) != 1)
        goto out;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_EncryptUpdate(ctx, mask, &len, sample, 16) != 1 || len != 16)
        goto out;
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int gen_x25519_public(uint8_t out[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY     *pkey = NULL;
    size_t        out_len = 32;
    int           ok = 0;
    if (!ctx)
        return 0;
    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_keygen(ctx, &pkey) == 1 && pkey &&
        EVP_PKEY_get_raw_public_key(pkey, out, &out_len) == 1 &&
        out_len == 32)
        ok = 1;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int append_alpn(uint8_t *data, size_t cap, size_t *off,
                       const char *alpn) {
    uint8_t list[256];
    size_t  list_off = 0;
    const char *p    = alpn && *alpn ? alpn : "h3";
    while (*p) {
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
        const char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t')
            p++;
        size_t n = (size_t)(p - start);
        if (n == 0 || n > 255 || list_off + 1 + n > sizeof(list))
            return 0;
        list[list_off++] = (uint8_t)n;
        memcpy(list + list_off, start, n);
        list_off += n;
    }
    if (list_off == 0) {
        list[0] = 2;
        list[1] = 'h';
        list[2] = '3';
        list_off = 3;
    }
    if (*off + 2 + list_off > cap)
        return 0;
    data[(*off)++] = (uint8_t)(list_off >> 8);
    data[(*off)++] = (uint8_t)list_off;
    memcpy(data + *off, list, list_off);
    *off += list_off;
    return 1;
}

static int append_extension(uint8_t *ext, size_t cap, size_t *off, uint16_t type,
                            const uint8_t *data, size_t data_len) {
    if (data_len > 65535)
        return 0;
    return append_u16(ext, cap, off, type) &&
           append_u16(ext, cap, off, (uint16_t)data_len) &&
           append_bytes(ext, cap, off, data, data_len);
}

static int build_client_hello(const QuicBuildConfig *conf, uint8_t *ch,
                              size_t cap, size_t *ch_len) {
    uint8_t ext[768];
    size_t  ext_off = 0;

    uint8_t sv[3] = {0x02, 0x03, 0x04};
    if (!append_extension(ext, sizeof(ext), &ext_off, 0x002b, sv, sizeof(sv)))
        return 0;

    uint8_t groups[4] = {0x00, 0x02, 0x00, 0x1d};
    if (!append_extension(ext, sizeof(ext), &ext_off, 0x000a, groups,
                          sizeof(groups)))
        return 0;

    uint8_t sigalgs[6] = {0x00, 0x04, 0x08, 0x04, 0x04, 0x03};
    if (!append_extension(ext, sizeof(ext), &ext_off, 0x000d, sigalgs,
                          sizeof(sigalgs)))
        return 0;

    uint8_t key[32];
    if (!gen_x25519_public(key))
        return 0;
    uint8_t share[40];
    size_t  so = 0;
    if (!append_u16(share, sizeof(share), &so, 38) ||
        !append_u16(share, sizeof(share), &so, 0x001d) ||
        !append_u16(share, sizeof(share), &so, 32) ||
        !append_bytes(share, sizeof(share), &so, key, 32))
        return 0;
    if (!append_extension(ext, sizeof(ext), &ext_off, 0x0033, share, so))
        return 0;

    uint8_t alpn[256];
    size_t  ao = 0;
    if (!append_alpn(alpn, sizeof(alpn), &ao, conf->alpn))
        return 0;
    if (!append_extension(ext, sizeof(ext), &ext_off, 0x0010, alpn, ao))
        return 0;

    uint8_t tp[128];
    size_t  to = 0;
    if (!put_varint(tp, sizeof(tp), &to, 0x0f) ||
        !put_varint(tp, sizeof(tp), &to, conf->scid_len) ||
        !append_bytes(tp, sizeof(tp), &to, conf->scid, conf->scid_len))
        return 0;
    {
        uint8_t val[4];
        size_t  vo = 0;
        if (!put_varint(val, sizeof(val), &vo, 1200))
            return 0;
        if (!put_varint(tp, sizeof(tp), &to, 0x03) ||
            !put_varint(tp, sizeof(tp), &to, vo) ||
            !append_bytes(tp, sizeof(tp), &to, val, vo))
            return 0;
    }
    if (!append_extension(ext, sizeof(ext), &ext_off, 0x0039, tp, to))
        return 0;

    if (conf->sni && *conf->sni) {
        size_t sni_len = strlen(conf->sni);
        if (sni_len == 0 || sni_len > 255)
            return 0;
        uint8_t sni[300];
        size_t  no = 0;
        if (!append_u16(sni, sizeof(sni), &no, (uint16_t)(sni_len + 3)) ||
            !append_u8(sni, sizeof(sni), &no, 0) ||
            !append_u16(sni, sizeof(sni), &no, (uint16_t)sni_len) ||
            !append_bytes(sni, sizeof(sni), &no, conf->sni, sni_len))
            return 0;
        if (!append_extension(ext, sizeof(ext), &ext_off, 0x0000, sni, no))
            return 0;
    }

    uint8_t body[1024];
    size_t  bo = 0;
    if (!append_u16(body, sizeof(body), &bo, 0x0303))
        return 0;
    uint8_t random[32];
    if (RAND_bytes(random, sizeof(random)) != 1 ||
        !append_bytes(body, sizeof(body), &bo, random, sizeof(random)) ||
        !append_u8(body, sizeof(body), &bo, 0))
        return 0;
    if (!append_u16(body, sizeof(body), &bo, 4) ||
        !append_u16(body, sizeof(body), &bo, 0x1301) ||
        !append_u16(body, sizeof(body), &bo, 0x1302) ||
        !append_u8(body, sizeof(body), &bo, 1) ||
        !append_u8(body, sizeof(body), &bo, 0) ||
        !append_u16(body, sizeof(body), &bo, (uint16_t)ext_off) ||
        !append_bytes(body, sizeof(body), &bo, ext, ext_off))
        return 0;

    size_t off = 0;
    if (bo > 0xffffff || !append_u8(ch, cap, &off, 0x01) ||
        !append_u24(ch, cap, &off, (uint32_t)bo) ||
        !append_bytes(ch, cap, &off, body, bo))
        return 0;
    *ch_len = off;
    return 1;
}

size_t quic_build_initial(const QuicBuildConfig *conf, uint8_t *buf,
                          size_t cap) {
    if (!conf || !buf || !conf->dcid || !conf->scid ||
        conf->dcid_len == 0 || conf->dcid_len > QUIC_MAX_CID_LEN ||
        conf->scid_len == 0 || conf->scid_len > QUIC_MAX_CID_LEN)
        return 0;

    uint8_t ch[1100];
    size_t  ch_len = 0;
    if (!build_client_hello(conf, ch, sizeof(ch), &ch_len))
        return 0;

    uint8_t frame[1200];
    size_t  fo = 0;
    if (!append_u8(frame, sizeof(frame), &fo, 0x06) || /* CRYPTO */
        !put_varint(frame, sizeof(frame), &fo, 0) ||
        !put_varint(frame, sizeof(frame), &fo, ch_len) ||
        !append_bytes(frame, sizeof(frame), &fo, ch, ch_len))
        return 0;
    size_t frame_len = fo;

    uint8_t key[QUIC_KEY_LEN], iv[QUIC_IV_LEN], hp[QUIC_HP_LEN];
    if (!derive_client_initial(conf->dcid, conf->dcid_len, key, iv, hp))
        return 0;

    size_t base = 1 + 4 + 1 + conf->dcid_len + 1 + conf->scid_len + 1;
    size_t payload_len = frame_len;
    size_t header_len  = 0;
    size_t total_len   = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t length_value = QUIC_PN_LEN + payload_len + QUIC_TAG_LEN;
        size_t   len_sz       = varint_len(length_value);
        header_len            = base + len_sz + QUIC_PN_LEN;
        size_t want_payload =
            QUIC_MIN_INITIAL_DATAGRAM > header_len + QUIC_TAG_LEN
                ? QUIC_MIN_INITIAL_DATAGRAM - header_len - QUIC_TAG_LEN
                : 0;
        if (want_payload > payload_len)
            payload_len = want_payload;
        total_len = header_len + payload_len + QUIC_TAG_LEN;
        if (total_len >= QUIC_MIN_INITIAL_DATAGRAM || want_payload <= payload_len)
            break;
    }
    if (payload_len < frame_len || total_len > cap)
        return 0;

    size_t h = 0;
    if (!append_u8(buf, cap, &h, 0xC0 | 0x01) ||
        !append_bytes(buf, cap, &h,
                      (uint8_t[]){0x00, 0x00, 0x00, 0x01}, 4) ||
        !append_u8(buf, cap, &h, (uint8_t)conf->dcid_len) ||
        !append_bytes(buf, cap, &h, conf->dcid, conf->dcid_len) ||
        !append_u8(buf, cap, &h, (uint8_t)conf->scid_len) ||
        !append_bytes(buf, cap, &h, conf->scid, conf->scid_len) ||
        !put_varint(buf, cap, &h, 0))
        return 0;
    uint64_t length_value = QUIC_PN_LEN + payload_len + QUIC_TAG_LEN;
    if (!put_varint(buf, cap, &h, length_value) ||
        !append_bytes(buf, cap, &h, (uint8_t[]){0, 0}, QUIC_PN_LEN))
        return 0;

    uint8_t *aad        = buf;
    size_t   aad_len    = h;
    uint8_t *plain      = buf + h;
    memset(plain, 0, payload_len);
    memcpy(plain, frame, frame_len);

    uint8_t tag[QUIC_TAG_LEN];
    if (!aes_gcm_encrypt(key, iv, aad, aad_len, plain, payload_len, plain, tag))
        return 0;
    memcpy(plain + payload_len, tag, sizeof(tag));

    size_t   pn_offset = h - QUIC_PN_LEN;
    uint8_t  mask[16];
    if (pn_offset + 4 + 16 > h + payload_len + QUIC_TAG_LEN ||
        !aes_ecb_mask(hp, buf + pn_offset + 4, mask))
        return 0;
    buf[0] ^= mask[0] & 0x0f;
    for (size_t i = 0; i < QUIC_PN_LEN; i++)
        buf[pn_offset + i] ^= mask[1 + i];

    return h + payload_len + QUIC_TAG_LEN;
}

const char *quic_response_type_name(enum QuicResponseType type) {
    switch (type) {
        case QUIC_RESPONSE_INITIAL:
            return "initial";
        case QUIC_RESPONSE_HANDSHAKE:
            return "handshake";
        case QUIC_RESPONSE_RETRY:
            return "retry";
        case QUIC_RESPONSE_VERSION_NEGOTIATION:
            return "version-negotiation";
        default:
            return "unknown";
    }
}

int quic_parse_response(const uint8_t *buf, size_t len,
                        const uint8_t *expected_scid, size_t expected_scid_len,
                        QuicResponseInfo *out) {
    if (!buf || len < 7 || !out)
        return 0;
    memset(out, 0, sizeof(*out));
    if (!(buf[0] & 0x80))
        return 0;

    size_t   off = 1;
    uint32_t version = get_u32_be(buf + off);
    off += 4;
    if (off >= len)
        return 0;
    size_t dcil = buf[off++];
    if (dcil > QUIC_MAX_CID_LEN || off + dcil + 1 > len)
        return 0;
    const uint8_t *dcid = buf + off;
    off += dcil;
    size_t scil = buf[off++];
    if (scil > QUIC_MAX_CID_LEN || off + scil > len)
        return 0;
    const uint8_t *scid = buf + off;
    off += scil;

    if (expected_scid && (dcil != expected_scid_len ||
                          memcmp(dcid, expected_scid, dcil) != 0))
        return 0;

    out->version  = version;
    out->dcid_len = dcil;
    memcpy(out->dcid, dcid, dcil);
    out->scid_len = scil;
    memcpy(out->scid, scid, scil);

    if (version == 0) {
        out->type = QUIC_RESPONSE_VERSION_NEGOTIATION;
        while (off + 4 <= len && out->versions_count < QUIC_MAX_VERSIONS) {
            out->versions[out->versions_count++] = get_u32_be(buf + off);
            off += 4;
        }
        return 1;
    }

    uint8_t type = (buf[0] >> 4) & 0x3;
    if (type == 3) {
        out->type      = QUIC_RESPONSE_RETRY;
        out->token_len = len - off;
        return 1;
    }

    uint64_t token_len = 0;
    if (type == 0) {
        if (!get_varint(buf, len, &off, &token_len) || off + token_len > len)
            return 0;
        out->token_len = (size_t)token_len;
        off += (size_t)token_len;
    }
    uint64_t packet_len = 0;
    if (!get_varint(buf, len, &off, &packet_len))
        return 0;
    if (packet_len > len - off)
        return 0;
    out->payload_len = (size_t)packet_len;
    out->type        = type == 0   ? QUIC_RESPONSE_INITIAL
                       : type == 2 ? QUIC_RESPONSE_HANDSHAKE
                                   : QUIC_RESPONSE_UNKNOWN;
    return out->type != QUIC_RESPONSE_UNKNOWN;
}

int proto_quic_selftest(void) {
    uint8_t dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t scid[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    QuicBuildConfig conf = {
        .version = QUIC_V1,
        .dcid = dcid,
        .dcid_len = sizeof(dcid),
        .scid = scid,
        .scid_len = sizeof(scid),
        .alpn = "h3",
    };
    uint8_t packet[2048];
    size_t  plen = quic_build_initial(&conf, packet, sizeof(packet));
    if (plen < QUIC_MIN_INITIAL_DATAGRAM)
        return 10;
    if (packet[1] != 0 || packet[2] != 0 || packet[3] != 0 || packet[4] != 1)
        return 11;

    uint8_t vn[64];
    size_t  o = 0;
    append_u8(vn, sizeof(vn), &o, 0xC0);
    append_bytes(vn, sizeof(vn), &o, (uint8_t[]){0, 0, 0, 0}, 4);
    append_u8(vn, sizeof(vn), &o, 8);
    append_bytes(vn, sizeof(vn), &o, scid, 8);
    append_u8(vn, sizeof(vn), &o, 8);
    append_bytes(vn, sizeof(vn), &o, dcid, 8);
    append_bytes(vn, sizeof(vn), &o, (uint8_t[]){0, 0, 0, 1, 0xfa, 0xce, 0xb0, 0x0c}, 8);

    QuicResponseInfo info;
    if (!quic_parse_response(vn, o, scid, sizeof(scid), &info) ||
        info.type != QUIC_RESPONSE_VERSION_NEGOTIATION ||
        info.versions_count != 2)
        return 2;

    uint8_t retry[64];
    o = 0;
    append_u8(retry, sizeof(retry), &o, 0xF0);
    append_bytes(retry, sizeof(retry), &o, (uint8_t[]){0, 0, 0, 1}, 4);
    append_u8(retry, sizeof(retry), &o, 8);
    append_bytes(retry, sizeof(retry), &o, scid, 8);
    append_u8(retry, sizeof(retry), &o, 8);
    append_bytes(retry, sizeof(retry), &o, dcid, 8);
    append_bytes(retry, sizeof(retry), &o, (uint8_t[]){1, 2, 3}, 3);
    if (!quic_parse_response(retry, o, scid, sizeof(scid), &info) ||
        info.type != QUIC_RESPONSE_RETRY || info.token_len != 3)
        return 3;

    if (quic_parse_response(vn, o, dcid, sizeof(dcid), &info))
        return 4;

    return 0;
}

#endif /* NOT_FOUND_OPENSSL */
