#ifndef QUIC_STATE_API_H
#define QUIC_STATE_API_H

/*
 * Internal API exposed by the optional quic-state ScanModule to a state probe.
 * The probe runs only after the QUIC/TLS handshake. Functions are called with
 * the quic-state flow lock already held; the callee must not block or call
 * back into quic-state.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../probe-modules/probe-modules.h"

bool quic_state_open_uni(ProbeState *state, uint64_t stream_type,
                         uint64_t *stream_id);
bool quic_state_open_bidi(ProbeState *state, uint64_t *stream_id);
bool quic_state_send_stream(ProbeState *state, uint64_t stream_id,
                            const void *data, size_t len, bool fin);

#endif
