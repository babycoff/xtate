#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe MqttProbe;

static const unsigned char mqtt_connect[] = {
    0x10, 0x11,                         /* CONNECT, remaining length 17 */
    0x00, 0x04, 'M', 'Q', 'T', 'T',    /* protocol name */
    0x04,                               /* MQTT 3.1.1 */
    0x02,                               /* clean session */
    0x00, 0x3c,                         /* keepalive 60 */
    0x00, 0x05, 'x', 't', 'a', 't', 'e' /* client id */
};

static size_t mqtt_make_payload(ProbeTarget *target,
                                unsigned char *payload_buf) {
    UNUSEDPARM(target);
    memcpy(payload_buf, mqtt_connect, sizeof(mqtt_connect));
    return sizeof(mqtt_connect);
}

static size_t mqtt_payload_length(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(mqtt_connect);
}

static unsigned mqtt_handle(unsigned th_idx, ProbeTarget *target,
                            const unsigned char *px, unsigned sizeof_px,
                            OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);

    if (sizeof_px < 4 || px[0] != 0x20) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mqtt");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not connack");
        return 0;
    }

    dach_append_banner(&item->probe_report, "mqtt_response", px, sizeof_px);
    dach_set_int(&item->probe_report, "mqtt_connack", 1);
    dach_set_int(&item->probe_report, "mqtt_session_present", px[2] & 1);
    dach_set_int(&item->probe_report, "mqtt_return_code", px[3]);
    dach_append_str(&item->probe_report, "mqtt_protocol", "3.1.1", 5);

    safe_strcpy(item->classification, OUT_CLS_SIZE, "mqtt");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "connack");
    item->level = px[3] == 0 ? OUT_SUCCESS : OUT_FAILURE;
    return 0;
}

Probe MqttProbe = {
    .name       = "mqtt",
    .type       = ProbeType_TCP,
    .short_desc = "MQTT 3.1.1 CONNECT and CONNACK return-code parse.",
    .desc = "Send a minimal MQTT 3.1.1 CONNECT with clean-session and client "
            "id `xtate`, then parse CONNACK session-present and return-code. "
            "No publish/subscribe or credentials are sent. Single slot.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &mqtt_make_payload,
    .get_payload_length_cb = &mqtt_payload_length,
    .handle_response_cb    = &mqtt_handle,
    .close_cb              = &probe_close_nothing,
};
