#include "probe-modules.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "../crypto/crypto-base64.h"
#include "../util-data/fine-malloc.h"
#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe SshKexProbe;

struct SshKexState {
    unsigned phase;
    unsigned char priv[32];
    unsigned char pub[32];
    bool have_keys;
};

static size_t put_u32(unsigned char *p, size_t off, unsigned v) {
    p[off] = (unsigned char)(v >> 24);
    p[off + 1] = (unsigned char)(v >> 16);
    p[off + 2] = (unsigned char)(v >> 8);
    p[off + 3] = (unsigned char)v;
    return off + 4;
}

static size_t put_str(unsigned char *p, size_t off, const void *s, size_t n) {
    off = put_u32(p, off, (unsigned)n);
    memcpy(p + off, s, n);
    return off + n;
}

static size_t put_list(unsigned char *p, size_t off, const char *s) {
    return put_str(p, off, s, strlen(s));
}

static size_t ssh_packet(unsigned char *out, const unsigned char *payload,
                         size_t len) {
    size_t pad = 8 - ((4 + 1 + len) % 8);
    if (pad < 4)
        pad += 8;
    size_t plen = 1 + len + pad;
    put_u32(out, 0, (unsigned)plen);
    out[4] = (unsigned char)pad;
    memcpy(out + 5, payload, len);
    memset(out + 5 + len, 0, pad);
    return 4 + plen;
}

static bool get_str(const unsigned char *p, size_t len, size_t *off,
                    const unsigned char **s, size_t *n) {
    if (*off + 4 > len)
        return false;
    unsigned v = ((unsigned)p[*off] << 24) | ((unsigned)p[*off + 1] << 16) |
                 ((unsigned)p[*off + 2] << 8) | p[*off + 3];
    *off += 4;
    if (*off + v > len)
        return false;
    *s = p + *off;
    *n = v;
    *off += v;
    return true;
}

static bool get_payload(const unsigned char *px, size_t len,
                        const unsigned char **payload, size_t *plen) {
    if (len < 6)
        return false;
    unsigned v = ((unsigned)px[0] << 24) | ((unsigned)px[1] << 16) |
                 ((unsigned)px[2] << 8) | px[3];
    if (v < 6 || v + 4 > len)
        return false;
    *payload = px + 5;
    *plen = v - 1 - px[4];
    return true;
}

static bool ssh_make_keys(struct SshKexState *st) {
    st->have_keys = false;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx)
            EVP_PKEY_CTX_free(ctx);
        return false;
    }
    size_t n = sizeof(st->priv);
    if (EVP_PKEY_get_raw_private_key(pkey, st->priv, &n) <= 0 ||
        EVP_PKEY_get_raw_public_key(pkey, st->pub, &n) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    st->have_keys = true;
    return true;
}

static size_t ssh_build_kexinit(unsigned char *out, struct SshKexState *st) {
    unsigned char payload[512];
    size_t off = 0;
    payload[off++] = 20;
    if (RAND_bytes(payload + off, 16) != 1)
        memset(payload + off, 0, 16);
    off += 16;
    off = put_list(payload, off, "curve25519-sha256");
    off = put_list(payload, off, "ssh-ed25519");
    off = put_list(payload, off, "aes128-ctr");
    off = put_list(payload, off, "aes128-ctr");
    off = put_list(payload, off, "hmac-sha2-256");
    off = put_list(payload, off, "hmac-sha2-256");
    off = put_list(payload, off, "none");
    off = put_list(payload, off, "none");
    off = put_list(payload, off, "");
    off = put_list(payload, off, "");
    payload[off++] = 0;
    off = put_u32(payload, off, 0);
    return ssh_packet(out, payload, off);
}

static size_t ssh_build_init(unsigned char *out, struct SshKexState *st) {
    unsigned char payload[64];
    size_t off = 0;
    payload[off++] = 30;
    off = put_str(payload, off, st->pub, sizeof(st->pub));
    return ssh_packet(out, payload, off);
}

static unsigned ssh_kex_handle(unsigned th_idx, ProbeTarget *target,
                               const unsigned char *px, unsigned sizeof_px,
                               OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 5) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "short reply");
        return 0;
    }
    const unsigned char *payload;
    size_t plen;
    if (!get_payload(px, sizeof_px, &payload, &plen) || plen < 1 ||
        payload[0] != 31) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not kex ecdh reply");
        return 0;
    }
    size_t off = 1;
    const unsigned char *hostkey, *server_pub, *sig;
    size_t hostkey_len, server_pub_len, sig_len;
    if (!get_str(payload, plen, &off, &hostkey, &hostkey_len) ||
        !get_str(payload, plen, &off, &server_pub, &server_pub_len) ||
        !get_str(payload, plen, &off, &sig, &sig_len)) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "bad kex reply");
        return 0;
    }
    const unsigned char *ktype;
    size_t ktype_len;
    size_t koff = 0;
    if (get_str(hostkey, hostkey_len, &koff, &ktype, &ktype_len) && ktype_len) {
        dach_append_str(&item->probe_report, "ssh_host_key_type", ktype,
                        ktype_len);
    }
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(hostkey, hostkey_len, digest);
    char b64[128];
    size_t b64len = base64_encode(b64, sizeof(b64), (const char *)digest,
                                  sizeof(digest));
    if (b64len) {
        b64[b64len] = 0;
        dach_append_str(&item->probe_report, "ssh_host_key_sha256", b64,
                        b64len);
    }
    dach_set_int(&item->probe_report, "ssh_host_key_bits",
                 (unsigned)(server_pub_len * 8));
    (void)sig_len;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "kex host key");
    item->level = OUT_SUCCESS;
    return 0;
}

static bool ssh_kex_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    struct SshKexState *st = CALLOC(1, sizeof(*st));
    if (!st)
        return false;
    state->data = st;
    return true;
}

static void ssh_kex_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    FREE(state->data);
    state->data = NULL;
}

static void ssh_kex_make_hello(DataPass *pass, ProbeState *state,
                               ProbeTarget *target) {
    UNUSEDPARM(target);
    struct SshKexState *st = state->data;
    if (!ssh_make_keys(st)) {
        pass->is_close = 1;
        return;
    }
    datapass_set_data(pass, (unsigned char *)"SSH-2.0-Xtate_1.0\r\n", 19,
                      false);
}

static unsigned ssh_kex_parse(DataPass *pass, ProbeState *state, OutConf *out,
                              ProbeTarget *target, const unsigned char *px,
                              unsigned sizeof_px) {
    struct SshKexState *st = state->data;
    if (st->phase == 0) {
        st->phase = 1;
        unsigned char buf[1200];
        size_t n = ssh_build_kexinit(buf, st);
        n += ssh_build_init(buf + n, st);
        datapass_set_data(pass, buf, n, true);
        return 0;
    }

    /* At this point the server may still send its KEXINIT before the reply. */
    if (sizeof_px < 6)
        return 0;
    const unsigned char *payload;
    size_t plen;
    if (!get_payload(px, sizeof_px, &payload, &plen) || plen < 1)
        return 0;
    if (payload[0] == 20)
        return 0; /* server KEXINIT, wait for KEX_ECDH_REPLY */
    if (payload[0] != 31)
        return 0;

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };
    ssh_kex_handle(0, target, px, sizeof_px, &item);
    output_result(out, &item);
    pass->is_close = 1;
    st->phase = 2;
    return 0;
}

Probe SshKexProbe = {
    .name       = "ssh-kex",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "SSH curve25519 KEX with host-key SHA256 fingerprint.",
    .desc = "Perform an unauthenticated curve25519-sha256 SSH key exchange and "
            "report the server host-key type and SHA256 fingerprint. No user "
            "authentication or command execution. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &ssh_kex_conn_init,
    .make_hello_cb     = &ssh_kex_make_hello,
    .parse_response_cb = &ssh_kex_parse,
    .conn_close_cb     = &ssh_kex_conn_close,
    .close_cb          = &probe_close_nothing,
};
