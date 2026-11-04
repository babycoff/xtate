#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

#define SSH_BANNER_MAX 128

struct SshConf {
    char     banner[SSH_BANNER_MAX];
    unsigned record_banner   : 1;
    unsigned record_software : 1;
    unsigned parse_kex       : 1;
    unsigned record_kexinit  : 1;
};

static struct SshConf ssh_conf = {
    .banner = "SSH-2.0-Xtate_1.0\r\n",
    .record_banner = 1,
    .record_software = 1,
    .parse_kex = 1,
    .record_kexinit = 0,
};

static ConfRes SET_send_banner(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || strlen(value) >= sizeof(ssh_conf.banner))
        return Conf_ERR;
    snprintf(ssh_conf.banner, sizeof(ssh_conf.banner), "%s", value);
    return Conf_OK;
}

static ConfRes SET_no_banner(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    ssh_conf.record_banner = !conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_no_software(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    ssh_conf.record_software = !conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_no_kex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    ssh_conf.parse_kex = !conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_record_kexinit(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    ssh_conf.record_kexinit = conf_parse_bool(value);
    return Conf_OK;
}

static ConfParam ssh_parameters[] = {
    {"send-banner",
     SET_send_banner,
     Type_ARG,
     {"banner", 0},
     "Identification string to send. Include the trailing CRLF; default is "
     "`SSH-2.0-Xtate_1.0\\r\\n`."},
    {"no-banner",
     SET_no_banner,
     Type_FLAG,
     {0},
     "Do not report the raw SSH identification banner."},
    {"no-software",
     SET_no_software,
     Type_FLAG,
     {0},
     "Do not report the software/comments part of the identification banner."},
    {"no-kex",
     SET_no_kex,
     Type_FLAG,
     {0},
     "Do not parse a coalesced SSH_MSG_KEXINIT packet."},
    {"record-kexinit",
     SET_record_kexinit,
     Type_FLAG,
     {0},
     "Also record the raw KEXINIT payload as a binary field."},
    {0}};

static size_t ssh_make_payload(ProbeTarget *target, unsigned char *payload_buf) {
    UNUSEDPARM(target);
    size_t len = strlen(ssh_conf.banner);
    memcpy(payload_buf, ssh_conf.banner, len);
    return len;
}

static size_t ssh_payload_length(ProbeTarget *target) {
    UNUSEDPARM(target);
    return strlen(ssh_conf.banner);
}

static bool ssh_name_list(const unsigned char *data, size_t data_len,
                          size_t *offset, char *out, size_t out_size) {
    if (*offset + 4 > data_len)
        return false;
    unsigned len = ((unsigned)data[*offset] << 24) |
                   ((unsigned)data[*offset + 1] << 16) |
                   ((unsigned)data[*offset + 2] << 8) |
                   (unsigned)data[*offset + 3];
    *offset += 4;
    if (*offset + len > data_len || len >= out_size)
        return false;
    memcpy(out, data + *offset, len);
    out[len] = '\0';
    *offset += len;
    return true;
}

static const char *const ssh_kex_list_names[] = {
    "ssh_kex_algorithms",
    "ssh_host_key_algorithms",
    "ssh_encryption_c2s",
    "ssh_encryption_s2c",
    "ssh_mac_c2s",
    "ssh_mac_s2c",
    "ssh_compression_c2s",
    "ssh_compression_s2c",
    "ssh_languages_c2s",
    "ssh_languages_s2c",
};

static void ssh_parse_kex(const unsigned char *data, size_t data_len,
                          OutItem *item) {
    if (data_len < 6)
        return;

    unsigned packet_len = ((unsigned)data[0] << 24) |
                          ((unsigned)data[1] << 16) |
                          ((unsigned)data[2] << 8) | (unsigned)data[3];
    if (packet_len < 6 || (size_t)packet_len + 4 > data_len)
        return;

    const unsigned char *payload = data + 5;
    size_t               payload_len = (size_t)packet_len - 1; /* padding */
    if (payload_len < 17 || payload[0] != 20)
        return;

    /* SSH_MSG_KEXINIT: message(1) + cookie(16) + ten name-lists. */
    size_t offset = 17;
    char   list[512];
    for (unsigned i = 0; i < 10; i++) {
        if (!ssh_name_list(payload, payload_len, &offset, list, sizeof(list)))
            return;
        if (list[0])
            dach_append_str(&item->probe_report, ssh_kex_list_names[i], list,
                            strlen(list));
    }

    if (offset + 1 <= payload_len) {
        dach_set_bool(&item->probe_report, "ssh_first_kex_follows",
                      payload[offset] != 0);
    }

    if (ssh_conf.record_kexinit)
        dach_append_bin(&item->probe_report, "ssh_kexinit", payload,
                        payload_len);
}

static unsigned ssh_handle(unsigned th_idx, ProbeTarget *target,
                           const unsigned char *px, unsigned sizeof_px,
                           OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);

    if (sizeof_px < 4 || memcmp(px, "SSH-", 4) != 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "invalid banner");
        return 0;
    }

    const char *line_end = memchr(px, '\n', sizeof_px);
    size_t      line_len = line_end ? (size_t)(line_end - (const char *)px)
                                    : sizeof_px;
    if (line_len && px[line_len - 1] == '\r')
        line_len--;

    if (ssh_conf.record_banner)
        dach_append_banner(&item->probe_report, "ssh_banner", px, line_len);
    dach_append_str(&item->probe_report, "ssh_protocol", px,
                    line_len < 7 ? line_len : 7);

    if (ssh_conf.record_software && line_len > 8) {
        const char *software = (const char *)px + 8;
        size_t      software_len = line_len - 8;
        const char *comment = memchr(software, ' ', software_len);
        size_t      part_len = comment ? (size_t)(comment - software)
                                       : software_len;
        if (part_len)
            dach_append_banner(&item->probe_report, "ssh_software", software,
                               part_len);
        if (comment && software_len > part_len + 1)
            dach_append_banner(&item->probe_report, "ssh_comment",
                               comment + 1, software_len - part_len - 1);
    }

    /* If the server coalesced KEXINIT into the same segment, parse it. */
    size_t packet_offset = line_end ? (size_t)(line_end - (const char *)px) + 1
                                    : sizeof_px;
    if (ssh_conf.parse_kex && packet_offset < sizeof_px)
        ssh_parse_kex(px + packet_offset, sizeof_px - packet_offset, item);

    safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "banner");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe SshProbe = {
    .name       = "ssh",
    .type       = ProbeType_TCP,
    .slots      = {.count = 1, .trigger = ProbeSlot_None, .continue_cb = NULL},
    .params     = ssh_parameters,
    .short_desc = "Read SSH banner and KEX/host-key algorithm lists.",
    .desc = "Send a configurable SSH identification string and report the "
            "server banner, protocol, software/comments, and the ten KEXINIT "
            "name-lists when the server coalesces KEXINIT with the banner. "
            "Use --send-banner, --no-banner/--no-software/--no-kex and "
            "--record-kexinit to control output. This is a single-slot probe.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &ssh_make_payload,
    .get_payload_length_cb = &ssh_payload_length,
    .handle_response_cb    = &ssh_handle,
    .close_cb              = &probe_close_nothing,
};
