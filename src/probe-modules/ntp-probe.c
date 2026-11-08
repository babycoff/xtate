#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe NtpProbe;

#define NTP_PACKET_LEN 48

static size_t ntp_make_payload(ProbeTarget *target, unsigned char *payload_buf) {
    memset(payload_buf, 0, NTP_PACKET_LEN);
    payload_buf[0] = 0x23; /* LI=0, VN=4, mode=3 (client) */
    payload_buf[40] = (unsigned char)(target->cookie >> 24);
    payload_buf[41] = (unsigned char)(target->cookie >> 16);
    payload_buf[42] = (unsigned char)(target->cookie >> 8);
    payload_buf[43] = (unsigned char)(target->cookie);
    return NTP_PACKET_LEN;
}

static bool ntp_validate(ProbeTarget *target, const unsigned char *px,
                         unsigned sizeof_px) {
    if (sizeof_px < NTP_PACKET_LEN || (px[0] & 0x7) != 4)
        return false;
    return px[24] == (unsigned char)(target->cookie >> 24) &&
           px[25] == (unsigned char)(target->cookie >> 16) &&
           px[26] == (unsigned char)(target->cookie >> 8) &&
           px[27] == (unsigned char)(target->cookie);
}

static unsigned ntp_handle(unsigned th_idx, ProbeTarget *target,
                           const unsigned char *px, unsigned sizeof_px,
                           OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);

    if (sizeof_px < NTP_PACKET_LEN) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ntp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "short response");
        return 0;
    }

    unsigned leap = px[0] >> 6;
    unsigned version = (px[0] >> 3) & 7;
    unsigned mode = px[0] & 7;
    char refid[20];
    snprintf(refid, sizeof(refid), "%02x%02x%02x%02x", px[12], px[13], px[14],
             px[15]);

    dach_set_int(&item->probe_report, "ntp_leap", leap);
    dach_set_int(&item->probe_report, "ntp_version", version);
    dach_set_int(&item->probe_report, "ntp_mode", mode);
    dach_set_int(&item->probe_report, "ntp_stratum", px[1]);
    dach_set_int(&item->probe_report, "ntp_poll", (signed char)px[2]);
    char precision[16];
    snprintf(precision, sizeof(precision), "%d", (signed char)px[3]);
    dach_append_str(&item->probe_report, "ntp_precision", precision,
                    strlen(precision));
    dach_append_str(&item->probe_report, "ntp_refid", refid, strlen(refid));
    dach_set_int(&item->probe_report, "ntp_root_delay",
                 ((unsigned)px[4] << 24) | ((unsigned)px[5] << 16) |
                     ((unsigned)px[6] << 8) | px[7]);
    dach_set_int(&item->probe_report, "ntp_root_dispersion",
                 ((unsigned)px[8] << 24) | ((unsigned)px[9] << 16) |
                     ((unsigned)px[10] << 8) | px[11]);

    safe_strcpy(item->classification, OUT_CLS_SIZE, "ntp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "response");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe NtpProbe = {
    .name       = "ntp",
    .type       = ProbeType_UDP,
    .short_desc = "NTP mode-3 request with structured server response.",
    .desc = "Send a 48-byte NTP client packet (version 4, mode 3) and validate "
            "the originate timestamp, then report leap/version/mode/stratum, "
            "poll/precision, refid and root delay/dispersion. No clock change "
            "is requested. Single slot.",
    .init_cb              = &probe_init_nothing,
    .make_payload_cb      = &ntp_make_payload,
    .validate_response_cb = &ntp_validate,
    .handle_response_cb   = &ntp_handle,
    .close_cb             = &probe_close_nothing,
};
