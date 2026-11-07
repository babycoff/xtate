#ifndef NOT_FOUND_OPENSSL

#include "probe-modules.h"

#include "../xconf.h"
#include "../proto/proto-quic.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

#include <stdio.h>
#include <string.h>

extern Probe QuicProbe;

struct QuicConf {
    char    *sni;
    char    *alpn;
    unsigned record_raw : 1;
};

static struct QuicConf quic_conf = {.alpn = NULL};

static ConfRes SET_sni(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (strlen(value) > 255) {
        LOG(LEVEL_ERROR, "quic sni must be <= 255 bytes\n");
        return Conf_ERR;
    }
    FREE(quic_conf.sni);
    quic_conf.sni = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_alpn(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || strlen(value) > 200) {
        LOG(LEVEL_ERROR, "quic alpn must be 1..200 bytes\n");
        return Conf_ERR;
    }
    FREE(quic_conf.alpn);
    quic_conf.alpn = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_record_raw(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    quic_conf.record_raw = conf_parse_bool(value);
    return Conf_OK;
}

static ConfParam quic_parameters[] = {
    {"sni",
     SET_sni,
     Type_ARG,
     {"server-name", "servername", 0},
     "Optional TLS SNI host name in the QUIC ClientHello. Targets are IPs, so "
     "this one name is applied to every target in the run."},
    {"alpn",
     SET_alpn,
     Type_ARG,
     {"alpn-protos", "alpn-proto", 0},
     "Comma/space separated ALPN list in the QUIC ClientHello. Default: h3. "
     "A negotiated ALPN is not observed by this capability probe."},
    {"record-raw",
     SET_record_raw,
     Type_FLAG,
     {"raw", 0},
     "Record the raw QUIC UDP response bytes. Useful for offline analysis, "
     "but it can be large for a Handshake packet."},
    {0}};

static uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

/* Derive stable client SCID/DCID from the stateless UDP cookie and ports.
 * The response is validated against the SCID without keeping per-target state. */
static void quic_ids_from_target(ProbeTarget *target, uint8_t scid[8],
                                 uint8_t dcid[8]) {
    uint64_t base = (uint64_t)target->cookie;
    base ^= ((uint64_t)target->target.port_them << 32);
    base ^= target->target.port_me;
    uint64_t a = splitmix64(base);
    uint64_t b = splitmix64(base ^ 0xd1b54a32d192ed03ULL);
    for (int i = 0; i < 8; i++) {
        scid[7 - i] = (uint8_t)(a >> (i * 8));
        dcid[7 - i] = (uint8_t)(b >> (i * 8));
    }
}

static size_t quic_make_payload(ProbeTarget *target,
                                unsigned char *payload_buf) {
    uint8_t scid[8], dcid[8];
    quic_ids_from_target(target, scid, dcid);
    QuicBuildConfig conf = {
        .version = 1,
        .dcid = dcid,
        .dcid_len = sizeof(dcid),
        .scid = scid,
        .scid_len = sizeof(scid),
        .sni = quic_conf.sni,
        .alpn = quic_conf.alpn ? quic_conf.alpn : "h3",
    };
    size_t len = quic_build_initial(&conf, payload_buf, PM_PAYLOAD_SIZE);
    if (len == 0) {
        LOG(LEVEL_WARN, "failed to build QUIC Initial packet\n");
    }
    return len;
}

static bool quic_validate_response(ProbeTarget *target, const unsigned char *px,
                                   unsigned sizeof_px) {
    uint8_t scid[8], dcid[8];
    quic_ids_from_target(target, scid, dcid);
    QuicResponseInfo info;
    return quic_parse_response(px, sizeof_px, scid, sizeof(scid), &info) != 0;
}

static void hex_cid(char *out, size_t out_size, const uint8_t *cid,
                    size_t cid_len) {
    if (!out_size)
        return;
    size_t off = 0;
    for (size_t i = 0; i < cid_len && off + 3 < out_size; i++)
        off += (size_t)snprintf(out + off, out_size - off, "%02x", cid[i]);
    out[off] = '\0';
}

static unsigned quic_handle_response(unsigned th_idx, ProbeTarget *target,
                                     const unsigned char *px, unsigned sizeof_px,
                                     OutItem *item) {
    UNUSEDPARM(th_idx);
    uint8_t scid[8], dcid[8];
    quic_ids_from_target(target, scid, dcid);
    QuicResponseInfo info;
    if (!quic_parse_response(px, sizeof_px, scid, sizeof(scid), &info)) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not quic");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "invalid response");
        return 0;
    }

    item->level = OUT_SUCCESS;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "quic response");
    safe_strcpy(item->reason, OUT_RSN_SIZE,
                quic_response_type_name(info.type));

    dach_append_str(&item->probe_report, "quic_response",
                    quic_response_type_name(info.type),
                    strlen(quic_response_type_name(info.type)));
    dach_set_int(&item->probe_report, "quic_version", info.version);
    char cid[2 * QUIC_MAX_CID_LEN + 1];
    hex_cid(cid, sizeof(cid), info.dcid, info.dcid_len);
    dach_append_str(&item->probe_report, "quic_dcid", cid, strlen(cid));
    hex_cid(cid, sizeof(cid), info.scid, info.scid_len);
    dach_append_str(&item->probe_report, "quic_scid", cid, strlen(cid));
    dach_set_int(&item->probe_report, "quic_token_len", info.token_len);
    dach_set_int(&item->probe_report, "quic_payload_len", info.payload_len);
    dach_set_int(&item->probe_report, "quic_versions_count",
                 info.versions_count);
    for (size_t i = 0; i < info.versions_count; i++) {
        char name[32];
        snprintf(name, sizeof(name), "quic_version_%zu", i);
        dach_set_int(&item->probe_report, name, info.versions[i]);
    }
    if (quic_conf.record_raw)
        dach_append_bin(&item->probe_report, "quic_raw", px, sizeof_px);

    return 0;
}

static bool quic_init(const XConf *xconf) {
    UNUSEDPARM(xconf);
    if (!quic_conf.alpn)
        quic_conf.alpn = STRDUP("h3");
    return true;
}

static void quic_close(void) {
    FREE(quic_conf.sni);
    FREE(quic_conf.alpn);
    quic_conf.sni = NULL;
    quic_conf.alpn = NULL;
}

Probe QuicProbe = {
    .name       = "quic",
    .type       = ProbeType_UDP,
    .params     = quic_parameters,
    .short_desc = "Send a QUIC v1 Initial and classify the transport response.",
    .desc =
        "QuicProbe sends one QUIC v1 Initial packet with a TLS 1.3 ClientHello "
        "and ALPN h3, using a unique client connection ID derived from the "
        "stateless UDP cookie. It classifies Version Negotiation, Retry, "
        "Initial, Handshake or an invalid/non-QUIC response.\n\n"
        "This is a QUIC capability probe. It does not complete a QUIC/TLS "
        "handshake, does not send an HTTP/3 request, and must not be reported "
        "as HTTP/3. A response containing a Handshake packet only proves that "
        "the server replied with QUIC transport bytes.\n\n"
        "Output: quic_response, quic_version, quic_dcid, quic_scid, "
        "quic_token_len, quic_payload_len, quic_versions_count and "
        "quic_version_<n> for Version Negotiation. --record-raw keeps the "
        "entire UDP response for offline analysis.\n\n"
        "Requires OpenSSL for HKDF-SHA256, AES-128-GCM and header protection.",

    .init_cb              = &quic_init,
    .make_payload_cb      = &quic_make_payload,
    .validate_response_cb = &quic_validate_response,
    .handle_response_cb   = &quic_handle_response,
    .close_cb             = &quic_close,
};

#endif /* NOT_FOUND_OPENSSL */
