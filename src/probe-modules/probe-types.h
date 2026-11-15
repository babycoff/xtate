#ifndef PROBE_TYPES_H
#define PROBE_TYPES_H

/*
 * Probe type is shared by scan modules (to declare their required probe) and
 * by probe modules. Keep it separate from the full probe registry so scan
 * headers do not need to include probe-modules.h.
 */
typedef enum ProbeType {
    ProbeType_NULL  = 0,
    ProbeType_TCP   = 1,
    ProbeType_UDP   = 2,
    ProbeType_STATE = 3,
} ProbeType;

/*
 * ProbeType_STATE describes the stateful-probe callback ABI.  It is not a
 * transport: the same ABI is used by tcp-state and quic-state.  A state probe
 * therefore declares the transports it can run over separately.
 */
typedef enum ProbeTransport {
    ProbeTransport_NONE = 0,
    ProbeTransport_TCP  = 1u << 0,
    ProbeTransport_QUIC = 1u << 1,
} ProbeTransport;

/* Optional callbacks that a transport needs from an application probe. */
typedef enum ProbeCapability {
    ProbeCapability_NONE       = 0,
    ProbeCapability_StreamData = 1u << 0,
} ProbeCapability;

#endif
