#ifdef HAVE_NGTCP2

/*
 * Experimental stateful QUIC scanner.
 *
 * ngtcp2 owns QUIC/TLS state and produces/consumes UDP payloads; Xtate keeps
 * control of the raw IPv4/IPv6/UDP packet, source ports, pacing, flow table,
 * timers and output.  The first milestone is handshake + certificate evidence;
 * HTTP/3/DoQ are application probes layered above this scanner.
 */

#include "scan-modules.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "../xconf.h"
#include "../probe-modules/probe-modules.h"
#include "../stack/stack-queue.h"
#include "../templ/templ-udp.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include "../output-modules/output-modules.h"
#include "../util-misc/misc.h"

#define QS_MAX_PENDING 8
#define QS_STATUS_SIZE 128
#define QS_BUCKETS 4096

extern Scanner QuicStateScan;

struct QuicFlow {
    struct QuicFlow *next;
    ipaddress        ip_them;
    ipaddress        ip_me;
    unsigned         port_them;
    unsigned         port_me;

    ngtcp2_conn               *conn;
    ngtcp2_crypto_conn_ref     conn_ref;
    gnutls_session_t           session;
    gnutls_certificate_credentials_t cred;
    struct sockaddr_storage    local;
    socklen_t                  local_len;
    struct sockaddr_storage    remote;
    socklen_t                  remote_len;

    ngtcp2_tstamp created_ts;
    ngtcp2_tstamp last_ts;
    unsigned      handshake_done : 1;
    unsigned      output_done : 1;
    unsigned      closing : 1;
    unsigned      probe_inited : 1;
    ProbeState    substate;
    uint8_t      *send_buf;
    size_t        send_buf_len;
};

static struct QuicConf {
    char    *alpn;
    char    *sni;
    unsigned max_flows;
    unsigned flow_timeout;
    unsigned max_udp_payload;
    unsigned handshake_timeout;
    unsigned initial_rtt_ms;
    unsigned max_data;
    unsigned max_stream_data;
    unsigned max_streams;
    unsigned idle_timeout_ms;
    unsigned cc_algo;
    unsigned no_cert : 1;
} qs_conf = {.alpn = NULL, .sni = NULL, .max_flows = 100000,
             .flow_timeout = 30, .max_udp_payload = 1200,
             .handshake_timeout = 10, .initial_rtt_ms = 100,
             .max_data = 1024 * 1024, .max_stream_data = 128 * 1024,
             .max_streams = 3, .idle_timeout_ms = 30000, .cc_algo = 0};

static struct QuicFlow *qs_flows[QS_BUCKETS];
static unsigned         qs_flow_count;
static unsigned         qs_flow_dropped;
static pthread_mutex_t  qs_lock = PTHREAD_MUTEX_INITIALIZER;
static NetStack        *qs_stack;
static Probe           *qs_probe;
static unsigned         qs_src_port_start;
static unsigned char   *qs_tx_px;
static size_t           qs_tx_cap;
static size_t           qs_tx_len;

static ConfRes SET_qs_alpn(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || !*value || strlen(value) > 200) {
        LOG(LEVEL_ERROR, "quic-state alpn must be 1..200 bytes\n");
        return Conf_ERR;
    }
    FREE(qs_conf.alpn);
    qs_conf.alpn = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_qs_sni(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (strlen(value) > 255) {
        LOG(LEVEL_ERROR, "quic-state sni must be <= 255 bytes\n");
        return Conf_ERR;
    }
    FREE(qs_conf.sni);
    qs_conf.sni = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_qs_max_flows(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    qs_conf.max_flows = conf_parse_int(value);
    if (qs_conf.max_flows < 1 || qs_conf.max_flows > 10000000) {
        LOG(LEVEL_ERROR, "quic-state max-flows must be 1..10000000\n");
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfRes SET_qs_timeout(void *conf, const char *name,
                              const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    qs_conf.flow_timeout = conf_parse_int(value);
    if (qs_conf.flow_timeout < 1 || qs_conf.flow_timeout > 3600) {
        LOG(LEVEL_ERROR, "quic-state flow-timeout must be 1..3600 seconds\n");
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfRes SET_qs_max_udp_payload(void *conf, const char *name,
                                      const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1200 || v > 65527) {
        LOG(LEVEL_ERROR, "quic-state max-udp-payload must be 1200..65527\n");
        return Conf_ERR;
    }
    qs_conf.max_udp_payload = v;
    return Conf_OK;
}

static ConfRes SET_qs_handshake_timeout(void *conf, const char *name,
                                        const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1 || v > 120) {
        LOG(LEVEL_ERROR, "quic-state handshake-timeout must be 1..120 seconds\n");
        return Conf_ERR;
    }
    qs_conf.handshake_timeout = v;
    return Conf_OK;
}

static ConfRes SET_qs_initial_rtt(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1 || v > 60000) {
        LOG(LEVEL_ERROR, "quic-state initial-rtt must be 1..60000 ms\n");
        return Conf_ERR;
    }
    qs_conf.initial_rtt_ms = v;
    return Conf_OK;
}

static ConfRes SET_qs_max_data(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1024 || v > (16u * 1024u * 1024u)) {
        LOG(LEVEL_ERROR, "quic-state max-data must be 1024..16777216\n");
        return Conf_ERR;
    }
    qs_conf.max_data = v;
    return Conf_OK;
}

static ConfRes SET_qs_max_stream_data(void *conf, const char *name,
                                      const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1024 || v > (16u * 1024u * 1024u)) {
        LOG(LEVEL_ERROR, "quic-state max-stream-data must be 1024..16777216\n");
        return Conf_ERR;
    }
    qs_conf.max_stream_data = v;
    return Conf_OK;
}

static ConfRes SET_qs_max_streams(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1 || v > 128) {
        LOG(LEVEL_ERROR, "quic-state max-streams must be 1..128\n");
        return Conf_ERR;
    }
    qs_conf.max_streams = v;
    return Conf_OK;
}

static ConfRes SET_qs_idle_timeout(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 100 || v > 3600000) {
        LOG(LEVEL_ERROR, "quic-state idle-timeout must be 100..3600000 ms\n");
        return Conf_ERR;
    }
    qs_conf.idle_timeout_ms = v;
    return Conf_OK;
}

static ConfRes SET_qs_cc_algo(void *conf, const char *name,
                              const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (conf_equals(value, "reno"))
        qs_conf.cc_algo = NGTCP2_CC_ALGO_RENO;
    else if (conf_equals(value, "cubic"))
        qs_conf.cc_algo = NGTCP2_CC_ALGO_CUBIC;
    else if (conf_equals(value, "bbr"))
        qs_conf.cc_algo = NGTCP2_CC_ALGO_BBR;
    else if (conf_equals(value, "bbr2"))
        qs_conf.cc_algo = NGTCP2_CC_ALGO_BBR2;
    else {
        LOG(LEVEL_ERROR, "quic-state cc-algo must be reno|cubic|bbr|bbr2\n");
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfRes SET_qs_no_cert(void *conf, const char *name,
                              const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    qs_conf.no_cert = conf_parse_bool(value);
    return Conf_OK;
}

static ConfParam qs_parameters[] = {
    {"alpn",
     SET_qs_alpn,
     Type_ARG,
     {"alpn-protos", "alpn-proto", 0},
     "ALPN protocol list used in the QUIC TLS handshake. The first token is "
     "used by this transport scanner; default h3."},
    {"sni",
     SET_qs_sni,
     Type_ARG,
     {"server-name", "servername", 0},
     "Optional TLS SNI host name for every QUIC flow in this run."},
    {"max-flows",
     SET_qs_max_flows,
     Type_ARG,
     {"flow-limit", 0},
     "Maximum number of concurrent QUIC flows tracked by this scanner. New "
     "flows are dropped when the budget is exhausted. Default 100000."},
    {"flow-timeout",
     SET_qs_timeout,
     Type_ARG,
     {"timeout", 0},
     "Maximum lifetime of a QUIC flow in seconds; default 30."},
    {"max-udp-payload",
     SET_qs_max_udp_payload,
     Type_ARG,
     {"udp-payload", 0},
     "Maximum QUIC UDP payload size in bytes (1200..65527); default 1200. "
     "Also advertised as max_udp_payload_size."},
    {"handshake-timeout",
     SET_qs_handshake_timeout,
     Type_ARG,
     {"hs-timeout", 0},
     "QUIC handshake timeout in seconds (1..120); default 10."},
    {"initial-rtt",
     SET_qs_initial_rtt,
     Type_ARG,
     {"rtt-ms", 0},
     "Initial RTT in milliseconds used by the QUIC loss detector (1..60000); "
     "default 100. This is a loss-timer hint, not a measured value."},
    {"max-data",
     SET_qs_max_data,
     Type_ARG,
     {"conn-data", 0},
     "Advertised connection-level flow-control limit in bytes "
     "(1024..16777216); default 1048576."},
    {"max-stream-data",
     SET_qs_max_stream_data,
     Type_ARG,
     {"stream-data", 0},
     "Advertised per-stream flow-control limit in bytes "
     "(1024..16777216); default 131072."},
    {"max-streams",
     SET_qs_max_streams,
     Type_ARG,
     {"streams", 0},
     "Advertised maximum unidirectional streams (1..128); default 3. "
     "HTTP/3 needs control/QPACK streams; DoQ usually needs one."},
    {"idle-timeout",
     SET_qs_idle_timeout,
     Type_ARG,
     {"idle-ms", 0},
     "Advertised QUIC idle timeout in milliseconds (100..3600000); "
     "default 30000."},
    {"cc-algo",
     SET_qs_cc_algo,
     Type_ARG,
     {"cc", "congestion-control", 0},
     "QUIC congestion-control algorithm: reno, cubic, bbr or bbr2; "
     "default reno."},
    {"no-cert",
     SET_qs_no_cert,
     Type_FLAG,
     {"skip-cert", 0},
     "Do not parse/emit the peer certificate fields; the handshake and ALPN "
     "are still reported."},
    {0}};

static uint64_t qs_timestamp(void) {
    struct timespec tp;
    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
        return 0;
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static ngtcp2_conn *qs_get_conn(ngtcp2_crypto_conn_ref *ref) {
    struct QuicFlow *flow = ref->user_data;
    return flow->conn;
}

static void qs_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *ctx) {
    UNUSEDPARM(ctx);
    gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

static int qs_new_cid(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                      size_t cidlen, void *user_data) {
    UNUSEDPARM(conn);
    UNUSEDPARM(user_data);
    if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0 ||
        gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) !=
            0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    return 0;
}

static int qs_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    UNUSEDPARM(conn);
    struct QuicFlow *flow = user_data;
    flow->handshake_done = 1;
    return 0;
}

static const uint8_t *qs_alpn_token(const char *list, size_t *len) {
    const char *p = list && *list ? list : "h3";
    while (*p == ',' || *p == ' ' || *p == '\t')
        p++;
    const char *start = p;
    while (*p && *p != ',' && *p != ' ' && *p != '\t')
        p++;
    *len = (size_t)(p - start);
    return (const uint8_t *)start;
}

static int qs_verify_none(gnutls_session_t session) {
    UNUSEDPARM(session);
    return 0;
}

static int qs_gnutls_hook(gnutls_session_t session, unsigned int htype,
                          unsigned when, unsigned int incoming,
                          const gnutls_datum_t *msg) {
    UNUSEDPARM(session); UNUSEDPARM(htype); UNUSEDPARM(when); UNUSEDPARM(incoming);
    UNUSEDPARM(msg);
    return 0;
}

static int qs_gnutls_init(struct QuicFlow *flow) {
    int rv = gnutls_certificate_allocate_credentials(&flow->cred);
    if (rv != 0)
        return -1;
    gnutls_certificate_set_x509_system_trust(flow->cred);
    gnutls_certificate_set_verify_function(flow->cred, qs_verify_none);

    rv = gnutls_init(&flow->session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                                         GNUTLS_NO_END_OF_EARLY_DATA);
    if (rv != 0)
        return -1;
    if (ngtcp2_crypto_gnutls_configure_client_session(flow->session) != 0)
        return -1;
    rv = gnutls_priority_set_direct(
        flow->session,
        "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:"
        "+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:"
        "+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:"
        "+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE",
        NULL);
    if (rv != 0)
        return -1;
    gnutls_handshake_set_hook_function(flow->session, GNUTLS_HANDSHAKE_ANY,
                                       GNUTLS_HOOK_POST, qs_gnutls_hook);
    gnutls_session_set_ptr(flow->session, &flow->conn_ref);
    rv = gnutls_credentials_set(flow->session, GNUTLS_CRD_CERTIFICATE,
                                flow->cred);
    if (rv != 0)
        return -1;

    size_t alpn_len = 0;
    const uint8_t *alpn = qs_alpn_token(qs_conf.alpn, &alpn_len);
    gnutls_datum_t alpn_datum = {(uint8_t *)alpn, (unsigned)alpn_len};
    if (alpn_len == 0 ||
        gnutls_alpn_set_protocols(flow->session, &alpn_datum, 1,
                                  GNUTLS_ALPN_MANDATORY) != 0)
        return -1;

    if (qs_conf.sni && *qs_conf.sni)
        gnutls_server_name_set(flow->session, GNUTLS_NAME_DNS, qs_conf.sni,
                               strlen(qs_conf.sni));
    return 0;
}

static void qs_fill_sockaddr(ipaddress ip, unsigned port,
                             struct sockaddr_storage *ss, socklen_t *len) {
    memset(ss, 0, sizeof(*ss));
    if (ip.version == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        sin->sin_addr.s_addr = htonl(ip.ipv4);
        *len = sizeof(*sin);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        for (unsigned i = 0; i < 8; i++) {
            sin6->sin6_addr.s6_addr[i] =
                (uint8_t)(ip.ipv6.hi >> ((7 - i) * 8));
            sin6->sin6_addr.s6_addr[8 + i] =
                (uint8_t)(ip.ipv6.lo >> ((7 - i) * 8));
        }
        *len = sizeof(*sin6);
    }
}

static int qs_quic_init(struct QuicFlow *flow) {
    qs_fill_sockaddr(flow->ip_me, flow->port_me, &flow->local,
                     &flow->local_len);
    qs_fill_sockaddr(flow->ip_them, flow->port_them, &flow->remote,
                     &flow->remote_len);

    ngtcp2_path path = {
        {(struct sockaddr *)&flow->local, flow->local_len},
        {(struct sockaddr *)&flow->remote, flow->remote_len},
        NULL,
    };
    ngtcp2_callbacks callbacks = {
        ngtcp2_crypto_client_initial_cb,
        NULL,
        ngtcp2_crypto_recv_crypto_data_cb,
        qs_handshake_completed,
        NULL,
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        ngtcp2_crypto_recv_retry_cb,
        NULL,
        NULL,
        qs_rand,
        qs_new_cid,
        NULL,
        ngtcp2_crypto_update_key_cb,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        NULL,
        NULL,
        NULL,
        ngtcp2_crypto_get_path_challenge_data_cb,
        NULL,
        ngtcp2_crypto_version_negotiation_cb,
        NULL,
        NULL,
        NULL,
    };
    ngtcp2_cid dcid, scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    if (gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen) != 0)
        return -1;
    scid.datalen = 8;
    if (gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen) != 0)
        return -1;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = qs_timestamp();
    settings.initial_rtt = (ngtcp2_duration)qs_conf.initial_rtt_ms *
                           NGTCP2_MILLISECONDS;
    settings.handshake_timeout = (ngtcp2_duration)qs_conf.handshake_timeout *
                                  NGTCP2_SECONDS;
    settings.max_tx_udp_payload_size = qs_conf.max_udp_payload;
    settings.cc_algo = (ngtcp2_cc_algo)qs_conf.cc_algo;

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = qs_conf.max_streams;
    params.initial_max_streams_bidi = 1;
    params.initial_max_stream_data_bidi_local = qs_conf.max_stream_data;
    params.initial_max_stream_data_bidi_remote = qs_conf.max_stream_data;
    params.initial_max_stream_data_uni = qs_conf.max_stream_data;
    params.initial_max_data = qs_conf.max_data;
    params.max_udp_payload_size = qs_conf.max_udp_payload;
    params.max_idle_timeout =
        (ngtcp2_duration)qs_conf.idle_timeout_ms * NGTCP2_MILLISECONDS;

    int rv = ngtcp2_conn_client_new(&flow->conn, &dcid, &scid, &path,
                                    NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                    &params, NULL, flow);
    if (rv != 0)
        return -1;
    ngtcp2_conn_set_tls_native_handle(flow->conn, flow->session);
    flow->conn_ref.get_conn  = qs_get_conn;
    flow->conn_ref.user_data = flow;
    return 0;
}

static int qs_send_payload(struct QuicFlow *flow, const uint8_t *payload,
                           size_t payload_len) {
    if (!payload_len)
        return -1;
    if (qs_tx_px) {
        size_t len = udp_create_packet(
            flow->ip_them, flow->port_them, flow->ip_me, flow->port_me, 0,
            (unsigned char *)payload, payload_len, qs_tx_px, qs_tx_cap);
        if (!len)
            return -1;
        qs_tx_len = len;
        qs_tx_px = NULL;
        return 0;
    }
    if (!qs_stack)
        return -1;
    PktBuf *pkt = stack_get_pktbuf(qs_stack);
    if (!pkt)
        return -1;
    size_t len = udp_create_packet(flow->ip_them, flow->port_them, flow->ip_me,
                                   flow->port_me, 0, (unsigned char *)payload,
                                   payload_len, pkt->px, PKT_BUF_SIZE);
    if (!len) {
        stack_release_pktbuf(qs_stack, pkt);
        return -1;
    }
    pkt->length = len;
    stack_transmit_pktbuf(qs_stack, pkt);
    return 0;
}

static int qs_flow_write(struct QuicFlow *flow) {
    if (!flow->send_buf || !flow->send_buf_len)
        return -1;
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;

    for (unsigned i = 0; i < QS_MAX_PENDING; i++) {
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_vec datav = {NULL, 0};
        ngtcp2_ssize wdatalen = 0;
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            flow->conn, &ps.path, &pi, flow->send_buf, flow->send_buf_len,
            &wdatalen,
            NGTCP2_WRITE_STREAM_FLAG_MORE, -1, &datav, 1, qs_timestamp());
        if (nwrite == NGTCP2_ERR_WRITE_MORE)
            continue;
        if (nwrite < 0)
            return -1;
        if (nwrite == 0)
            return 0;
        if (qs_send_payload(flow, flow->send_buf, (size_t)nwrite) != 0)
            return -1;
    }
    return 0;
}

static void qs_flow_free(struct QuicFlow *flow) {
    if (flow->probe_inited && qs_probe)
        qs_probe->conn_close_cb(&flow->substate, NULL);
    if (flow->conn)
        ngtcp2_conn_del(flow->conn);
    if (flow->session)
        gnutls_deinit(flow->session);
    if (flow->cred)
        gnutls_certificate_free_credentials(flow->cred);
    FREE(flow->send_buf);
    FREE(flow);
}

static unsigned qs_flow_hash(ipaddress ip_them, unsigned port_them,
                             ipaddress ip_me, unsigned port_me) {
    uint64_t h = 1469598103934665603ULL;
    uint64_t a = ip_them.version == 4 ? ip_them.ipv4
                                      : (ip_them.ipv6.hi ^ ip_them.ipv6.lo);
    uint64_t b = ip_them.version == 4 ? ip_me.ipv4
                                      : (ip_me.ipv6.hi ^ ip_me.ipv6.lo);
    h = (h ^ a) * 1099511628211ULL;
    h = (h ^ b) * 1099511628211ULL;
    h = (h ^ port_them) * 1099511628211ULL;
    h = (h ^ port_me) * 1099511628211ULL;
    return (unsigned)(h % QS_BUCKETS);
}

static struct QuicFlow *qs_flow_find(ipaddress ip_them, unsigned port_them,
                                     ipaddress ip_me, unsigned port_me) {
    unsigned b = qs_flow_hash(ip_them, port_them, ip_me, port_me);
    for (struct QuicFlow *f = qs_flows[b]; f; f = f->next) {
        if (f->port_them == port_them && f->port_me == port_me &&
            ipaddress_is_equal(f->ip_them, ip_them) &&
            ipaddress_is_equal(f->ip_me, ip_me))
            return f;
    }
    return NULL;
}

static struct QuicFlow *qs_flow_new(ipaddress ip_them, unsigned port_them,
                                    ipaddress ip_me, unsigned port_me) {
    struct QuicFlow *flow = CALLOC(1, sizeof(*flow));
    if (!flow)
        return NULL;
    flow->ip_them = ip_them;
    flow->ip_me = ip_me;
    flow->port_them = port_them;
    flow->port_me = port_me;
    flow->created_ts = flow->last_ts = qs_timestamp();
    flow->send_buf_len = qs_conf.max_udp_payload;
    flow->send_buf = MALLOC(flow->send_buf_len);
    if (!flow->send_buf) {
        FREE(flow);
        return NULL;
    }
    if (qs_gnutls_init(flow) != 0) {
        LOG(LEVEL_ERROR, "quic-state: GnuTLS flow init failed\n");
        qs_flow_free(flow);
        return NULL;
    }
    if (qs_quic_init(flow) != 0) {
        LOG(LEVEL_ERROR, "quic-state: QUIC flow init failed\n");
        qs_flow_free(flow);
        return NULL;
    }
    unsigned b = qs_flow_hash(ip_them, port_them, ip_me, port_me);
    flow->next = qs_flows[b];
    qs_flows[b] = flow;
    qs_flow_count++;
    return flow;
}

static void qs_emit_cert(struct QuicFlow *flow, OutItem *item) {
    if (!flow->session)
        return;
    const gnutls_datum_t *certs = NULL;
    unsigned int n = 0;
    certs = gnutls_certificate_get_peers(flow->session, &n);
    if (!certs || n == 0)
        return;
    gnutls_x509_crt_t crt = NULL;
    if (gnutls_x509_crt_init(&crt) != 0)
        return;
    if (gnutls_x509_crt_import(crt, &certs[0], GNUTLS_X509_FMT_DER) != 0) {
        gnutls_x509_crt_deinit(crt);
        return;
    }
    char   dn[512];
    size_t dn_len = sizeof(dn);
    if (gnutls_x509_crt_get_dn(crt, dn, &dn_len) == 0 && dn_len)
        dach_append_str(&item->probe_report, "quic_cert_subject", dn,
                        strlen(dn));
    dn_len = sizeof(dn);
    if (gnutls_x509_crt_get_issuer_dn(crt, dn, &dn_len) == 0 && dn_len)
        dach_append_str(&item->probe_report, "quic_cert_issuer", dn,
                        strlen(dn));
    unsigned char fp[64];
    size_t        fp_len = sizeof(fp);
    if (gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_SHA256, fp,
                                        &fp_len) == 0) {
        char hex[3 * sizeof(fp) + 1];
        size_t off = 0;
        for (size_t i = 0; i < fp_len && off + 3 < sizeof(hex); i++)
            off += (size_t)snprintf(hex + off, sizeof(hex) - off, "%02x",
                                    fp[i]);
        hex[off] = '\0';
        dach_append_str(&item->probe_report, "quic_cert_sha256", hex,
                        strlen(hex));
    }
    gnutls_x509_crt_deinit(crt);
}

static void qs_emit(struct QuicFlow *flow, OutItem *item) {
    item->no_output = 0;
    item->level = OUT_SUCCESS;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "quic handshake");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "handshake completed");
    dach_set_int(&item->probe_report, "quic_version", NGTCP2_PROTO_VER_V1);
    const char *proto = gnutls_protocol_get_name(
        gnutls_protocol_get_version(flow->session));
    if (proto)
        dach_append_str(&item->probe_report, "quic_tls_version", proto,
                        strlen(proto));
    gnutls_datum_t alpn = {0};
    if (gnutls_alpn_get_selected_protocol(flow->session, &alpn) == 0 &&
        alpn.size)
        dach_append_str(&item->probe_report, "quic_alpn", (const char *)alpn.data,
                        alpn.size);
    if (!qs_conf.no_cert)
        qs_emit_cert(flow, item);
    flow->output_done = 1;
}

static bool qs_init(const XConf *xconf) {
    qs_stack = xconf->stack;
    qs_probe = xconf->probe;
    qs_src_port_start = xconf->nic.src.port.first;
    if (!qs_conf.alpn)
        qs_conf.alpn = STRDUP("h3");
    if (gnutls_global_init() != 0)
        return false;
    return true;
}

static bool qs_transmit(uint64_t entropy, ScanTarget *target,
                        unsigned char *px, size_t *len) {
    UNUSEDPARM(entropy);
    pthread_mutex_lock(&qs_lock);
    unsigned port_me = qs_src_port_start + target->index;
    struct QuicFlow *flow = qs_flow_find(target->target.ip_them,
                                         target->target.port_them,
                                         target->target.ip_me, port_me);
    if (!flow) {
        if (qs_flow_count >= qs_conf.max_flows) {
            qs_flow_dropped++;
            pthread_mutex_unlock(&qs_lock);
            return false;
        }
        flow = qs_flow_new(target->target.ip_them, target->target.port_them,
                           target->target.ip_me, port_me);
    }
    qs_tx_px = px;
    qs_tx_cap = PKT_BUF_SIZE;
    qs_tx_len = 0;
    if (flow)
        qs_flow_write(flow);
    qs_tx_px = NULL;
    *len = qs_tx_len;
    pthread_mutex_unlock(&qs_lock);
    return false;
}

static void qs_validate(uint64_t entropy, Recved *recved, PreHandle *pre) {
    UNUSEDPARM(entropy);
    if (recved->parsed.found == FOUND_UDP && recved->is_myip) {
        pre->go_record = 1;
        pre->go_dedup  = 1;
        pre->no_dedup  = 1;
    }
}

static void qs_handle(unsigned th_idx, uint64_t entropy, ValidPacket *valid_pkt,
                      OutItem *item, NetStack *stack) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(entropy);
    UNUSEDPARM(stack);
    item->no_output = 1;
    Recved *r = &valid_pkt->recved;
    if (r->parsed.found != FOUND_UDP)
        return;

    pthread_mutex_lock(&qs_lock);
    struct QuicFlow *flow = qs_flow_find(r->parsed.src_ip, r->parsed.port_src,
                                         r->parsed.dst_ip, r->parsed.port_dst);
    if (!flow) {
        pthread_mutex_unlock(&qs_lock);
        return;
    }
    flow->last_ts = qs_timestamp();
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ps.path.local.addr = (struct sockaddr *)&flow->local;
    ps.path.local.addrlen = flow->local_len;
    ps.path.remote.addr = (struct sockaddr *)&flow->remote;
    ps.path.remote.addrlen = flow->remote_len;
    ngtcp2_pkt_info pi = {0};
    const unsigned char *payload = r->packet + r->parsed.app_offset;
    unsigned payload_len = r->parsed.app_length;
    int rv = ngtcp2_conn_read_pkt(flow->conn, &ps.path, &pi, payload,
                                  payload_len, qs_timestamp());
    if (rv != 0) {
        if (!flow->handshake_done && !flow->output_done) {
            item->no_output = 0;
            item->level = OUT_FAILURE;
            safe_strcpy(item->classification, OUT_CLS_SIZE, "quic handshake");
            safe_strcpy(item->reason, OUT_RSN_SIZE, ngtcp2_strerror(rv));
            flow->output_done = 1;
        }
        flow->closing = 1;
        pthread_mutex_unlock(&qs_lock);
        return;
    }
    if (flow->handshake_done && !flow->output_done) {
        qs_emit(flow, item);
        if (qs_probe && !flow->probe_inited) {
            if (qs_probe->conn_init_cb(&flow->substate, NULL)) {
                flow->probe_inited = 1;
                DataPass pass = {0};
                qs_probe->make_hello_cb(&pass, &flow->substate, NULL);
                if (pass.is_close)
                    flow->closing = 1;
            } else {
                flow->closing = 1;
            }
        }
    }
    if (!flow->closing)
        qs_flow_write(flow);
    pthread_mutex_unlock(&qs_lock);
}

static void qs_poll(unsigned th_idx) {
    UNUSEDPARM(th_idx);
    ngtcp2_tstamp now = qs_timestamp();
    pthread_mutex_lock(&qs_lock);
    for (unsigned b = 0; b < QS_BUCKETS; b++) {
        struct QuicFlow **pp = &qs_flows[b];
        while (*pp) {
            struct QuicFlow *flow = *pp;
            if (flow->closing ||
                now - flow->created_ts > (ngtcp2_tstamp)qs_conf.flow_timeout *
                                             NGTCP2_SECONDS) {
                *pp = flow->next;
                qs_flow_free(flow);
                if (qs_flow_count)
                    qs_flow_count--;
                continue;
            }
            if (ngtcp2_conn_get_expiry(flow->conn) <= now) {
                if (ngtcp2_conn_handle_expiry(flow->conn, now) != 0)
                    flow->closing = 1;
                else
                    qs_flow_write(flow);
            }
            pp = &flow->next;
        }
    }
    pthread_mutex_unlock(&qs_lock);
}

static void qs_close(void) {
    pthread_mutex_lock(&qs_lock);
    for (unsigned b = 0; b < QS_BUCKETS; b++) {
        while (qs_flows[b]) {
            struct QuicFlow *flow = qs_flows[b];
            qs_flows[b] = flow->next;
            qs_flow_free(flow);
        }
    }
    qs_flow_count = 0;
    pthread_mutex_unlock(&qs_lock);
    FREE(qs_conf.alpn);
    FREE(qs_conf.sni);
    gnutls_global_deinit();
}

static void qs_status(char *status) {
    snprintf(status, QS_STATUS_SIZE, "quic flows=%u dropped=%u", qs_flow_count,
             qs_flow_dropped);
}

Scanner QuicStateScan = {
    .name       = "quic-state",
    .required_probe_type = ProbeType_STATE,
    .bpf_filter = "udp",
    .params     = qs_parameters,
    .short_desc = "Stateful QUIC transport scanner for handshake evidence.",
    .desc =
        "QuicStateScan tracks QUIC flows over raw UDP and uses ngtcp2/GnuTLS "
        "for the QUIC/TLS handshake. Xtate retains control of IPv4/IPv6/UDP "
        "headers, source ports, pacing, flow budgets, timers and output. "
        "The first milestone emits QUIC/TLS/certificate evidence and supports "
        "a state subprobe; HTTP/3 and DoQ are application probes layered above "
        "this transport. Requires an ngtcp2/GnuTLS build.",
    .init_cb     = &qs_init,
    .transmit_cb = &qs_transmit,
    .validate_cb = &qs_validate,
    .handle_cb   = &qs_handle,
    .poll_cb     = &qs_poll,
    .close_cb    = &qs_close,
    .status_cb   = &qs_status,
};

#endif /* HAVE_NGTCP2 */
