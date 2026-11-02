#ifndef SCAN_TYPES_H
#define SCAN_TYPES_H

/*
 * Packet/result data types exchanged between the transmit, receive and
 * scan-module layers. Kept separate from the scan-module registry so these
 * plain data types can be included without pulling in every callback and
 * module declaration.
 */

#include "../target/target.h"
#include "../target/target-ipaddress.h"
#include "../proto/proto-preprocess.h"

/* A target as seen by a ScanModule during transmit. */
typedef struct ScanModuleTarget {
    Target   target;
    unsigned index; /* multi-packet target index */
} ScanTarget;

/* A received packet after preprocessing, before scan-specific validation. */
typedef struct PacketReceived {
    PreInfo        parsed;
    unsigned char *packet;
    unsigned       length;
    unsigned       secs;
    unsigned       usecs;
    unsigned       is_myip   : 1;
    unsigned       is_myport : 1;
} Recved;

typedef struct PacketValidated {
    Recved   recved;
    unsigned repeats;
} ValidPacket;

/* Pre-handle decisions: record and/or deduplicate a received packet. */
typedef struct PacketPreHandle {
    unsigned  go_record : 1;
    unsigned  no_record : 1;
    unsigned  go_dedup  : 1;
    unsigned  no_dedup  : 1;
    ipaddress dedup_ip_them;
    unsigned  dedup_port_them;
    ipaddress dedup_ip_me;
    unsigned  dedup_port_me;
    unsigned  dedup_type;
} PreHandle;

#endif
