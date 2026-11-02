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

#endif
