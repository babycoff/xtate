#ifndef PROTO_QUIC_H
#define PROTO_QUIC_H

#include <stddef.h>
#include <stdint.h>

#define QUIC_MIN_INITIAL_DATAGRAM 1200
#define QUIC_MAX_CID_LEN 20
#define QUIC_MAX_VERSIONS 8

enum QuicResponseType {
    QUIC_RESPONSE_UNKNOWN = 0,
    QUIC_RESPONSE_INITIAL,
    QUIC_RESPONSE_HANDSHAKE,
    QUIC_RESPONSE_RETRY,
    QUIC_RESPONSE_VERSION_NEGOTIATION,
};

typedef struct QuicBuildConfig {
    uint32_t       version;
    const uint8_t *dcid;
    size_t         dcid_len;
    const uint8_t *scid;
    size_t         scid_len;
    const char    *sni;  /* optional */
    const char    *alpn; /* comma/space separated; default h3 */
} QuicBuildConfig;

typedef struct QuicResponseInfo {
    enum QuicResponseType type;
    uint32_t               version;
    uint8_t                dcid[QUIC_MAX_CID_LEN];
    size_t                 dcid_len;
    uint8_t                scid[QUIC_MAX_CID_LEN];
    size_t                 scid_len;
    uint32_t               versions[QUIC_MAX_VERSIONS];
    size_t                 versions_count;
    size_t                 token_len;
    size_t                 payload_len;
} QuicResponseInfo;

/* Build one QUIC v1 Initial packet. Returns the datagram length, or 0. */
size_t quic_build_initial(const QuicBuildConfig *conf, uint8_t *buf,
                          size_t cap);

/* Parse a long-header QUIC response and validate its DCID against
 * expected_scid. Returns 1 on success, 0 on failure/not QUIC. */
int quic_parse_response(const uint8_t *buf, size_t len,
                        const uint8_t *expected_scid, size_t expected_scid_len,
                        QuicResponseInfo *out);

const char *quic_response_type_name(enum QuicResponseType type);

int proto_quic_selftest(void);

#endif
