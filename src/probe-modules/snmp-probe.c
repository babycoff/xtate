#include "probe-modules.h"

#include "../xconf.h"
#include "../smack/smack.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/data-chain.h"

#define SNMP_DACH_NAME "result"

/*for internal x-ref*/
extern Probe SnmpProbe;

static const unsigned char default_snmp_req[] =
    "\x30\x39"
    "\x02\x01\x00"             /* version */
    "\x04\x06public"           /* community = public */
    "\xa0\x2c"                 /* type = GET */
    "\x02\x04\x00\x00\x00\x00" /* transaction id = ???? */
    "\x02\x01\x00"             /* error = 0 */
    "\x02\x01\x00"             /* error index = 0 */
    "\x30\x1e"
    "\x30\x0d"
    "\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x01\x00" /*sysName*/
    "\x05\x00" /*^^^^_____IDS LULZ HAH HA HAH*/
    "\x30\x0d"
    "\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x05\x00" /*sysDesc*/
    "\x05\x00" /*^^^^_____IDS LULZ HAH HA HAH*/
    ;

struct SnmpConf {
    struct SMACK **global_mibs;
    unsigned       mib_count;
};

static struct SnmpConf snmp_conf = {0};

/****************************************************************************
 * We parse an SNMP packet into this structure
 ****************************************************************************/
struct SNMP {
    uint64_t             version;
    uint64_t             pdu_tag;
    const unsigned char *community;
    uint64_t             community_length;
    uint64_t             request_id;
    uint64_t             error_index;
    uint64_t             error_status;
};

/****************************************************************************
 * This is the "compiled MIB" essentially. At program startup, we compile
 * this into an OID tree. We use this to replace OIDs with names.
 ****************************************************************************/
static struct SnmpOid {
    const char *oid;
    const char *name;
} mib[] = {
    {"43", "iso.org"},
    {"43.6", "dod"},
    {"43.6.1", "inet"},
    {"43.6.1.2", "mgmt"},
    {"43.6.1.2.1", "mib2"},
    {"43.6.1.2.1.", "sys"},
    {"43.6.1.2.1.1.1", "sysDescr"},
    {"43.6.1.2.1.1.2", "sysObjectID"},
    {"43.6.1.2.1.1.3", "sysUpTime"},
    {"43.6.1.2.1.1.4", "sysContact"},
    {"43.6.1.2.1.1.5", "sysName"},
    {"43.6.1.2.1.1.6", "sysLocation"},
    {"43.6.1.2.1.1.7", "sysServices"},
    {"43.6.1.4", "priv"},
    {"43.6.1.4.1", "enterprise"},
    {"43.6.1.4.1.2001", "okidata"},
    {0, 0},
};

/****************************************************************************
 * An ASN.1 length field has two formats.
 *  - if the high-order bit of the length byte is clear, then it
 *    encodes a length between 0 and 127.
 *  - if the high-order bit is set, then the length byte is a
 *    length-of-length, where the low order bits dictate the number of
 *    remaining bytes to be used in the length.
 ****************************************************************************/
static uint64_t asn1_length(const unsigned char *px, uint64_t length,
                            uint64_t *r_offset) {
    uint64_t result;

    /* check for errors */
    if ((*r_offset >= length) ||
        ((px[*r_offset] & 0x80) &&
         ((*r_offset) + (px[*r_offset] & 0x7F) >= length))) {
        *r_offset = length;
        return 0xFFFFffff;
    }

    /* grab the byte's value */
    result = px[(*r_offset)++];

    if (result & 0x80) {
        unsigned length_of_length = result & 0x7F;
        if (length_of_length == 0) {
            *r_offset = length;
            return 0xFFFFffff;
        }
        result = 0;
        while (length_of_length) {
            result = result * 256 + px[(*r_offset)++];
            if (result > 0x10000) {
                *r_offset = length;
                return 0xFFFFffff;
            }
            length_of_length--;
        }
    }
    return result;
}

/****************************************************************************
 * Extract an integer. Note
 ****************************************************************************/
static uint64_t asn1_integer(const unsigned char *px, uint64_t length,
                             uint64_t *r_offset) {
    uint64_t int_length;
    uint64_t result;

    if (px[(*r_offset)++] != 0x02) {
        *r_offset = length;
        return 0xFFFFffff;
    }

    int_length = asn1_length(px, length, r_offset);
    if (int_length == 0xFFFFffff) {
        *r_offset = length;
        return 0xFFFFffff;
    }
    if (*r_offset + int_length > length) {
        *r_offset = length;
        return 0xFFFFffff;
    }
    if (int_length > 20) {
        *r_offset = length;
        return 0xFFFFffff;
    }

    result = 0;
    while (int_length--)
        result = result * 256 + px[(*r_offset)++];

    return result;
}

/****************************************************************************
 ****************************************************************************/
static unsigned asn1_tag(const unsigned char *px, uint64_t length,
                         uint64_t *r_offset) {
    if (*r_offset >= length)
        return 0;
    return px[(*r_offset)++];
}

/****************************************************************************
 ****************************************************************************/
static uint64_t next_id(const unsigned char *oid, unsigned *offset,
                        uint64_t oid_length) {
    uint64_t result = 0;
    while (*offset < oid_length && (oid[*offset] & 0x80)) {
        result <<= 7;
        result |= oid[(*offset)++] & 0x7F;
    }
    if (*offset < oid_length) {
        result <<= 7;
        result |= oid[(*offset)++] & 0x7F;
    }
    return result;
}

/****************************************************************************
 ****************************************************************************/
static void snmp_banner_oid(struct SMACK *global_mib, const unsigned char *oid,
                            size_t oid_length, DataChain *dach) {
    unsigned i;
    size_t   id;
    unsigned offset;
    unsigned state;
    size_t   found_id     = SMACK_NOT_FOUND;
    size_t   found_offset = 0;

    /*
     * Find the var name
     */
    state = 0;
    for (offset = 0; offset < oid_length;) {
        id = smack_search_next(global_mib, &state, oid, &offset,
                               (unsigned)oid_length);
        if (id != SMACK_NOT_FOUND) {
            found_id     = id;
            found_offset = offset;
        }
    }

    /* Do the string */
    if (found_id != SMACK_NOT_FOUND) {
        const char *str = mib[found_id].name;
        dach_append_str(dach, SNMP_DACH_NAME, str, strlen(str));
    }

    /* Do remaining OIDs */
    for (i = (unsigned)found_offset; i < oid_length;) {
        uint64_t x = next_id(oid, &i, oid_length);

        if (x == 0 && i >= oid_length)
            break;

        dach_printf(dach, SNMP_DACH_NAME, ".%" PRIu64 "", x);
    }
}

/****************************************************************************
 ****************************************************************************/
static void snmp_banner(struct SMACK *global_mib, const unsigned char *oid,
                        size_t oid_length, uint64_t var_tag,
                        const unsigned char *var, size_t var_length,
                        DataChain *dach) {
    size_t i;

    dach_append_char(dach, SNMP_DACH_NAME, '[', LinkType_String);
    /* print the OID */
    snmp_banner_oid(global_mib, oid, oid_length, dach);

    dach_append_str(dach, SNMP_DACH_NAME, ": ", 2);

    switch (var_tag) {
        case 2: {
            uint64_t result = 0;
            for (i = 0; i < var_length; i++)
                result = result << 8 | var[i];
            dach_printf(dach, SNMP_DACH_NAME, "%" PRIu64 "", result);
        } break;
        case 6:
            snmp_banner_oid(global_mib, var, var_length, dach);
            break;
        case 4:
        default:
            dach_append_banner(dach, SNMP_DACH_NAME, var, var_length);
            break;
    }

    dach_append_char(dach, SNMP_DACH_NAME, ']', LinkType_String);
}

/****************************************************************************
 ****************************************************************************/
static unsigned snmp_set_cookie(unsigned char *px, size_t length,
                                unsigned seqno) {
    uint64_t offset = 0;
    uint64_t outer_length;
    uint64_t version;
    uint64_t tag;
    uint64_t len;

    /* tag */
    if (asn1_tag(px, length, &offset) != 0x30)
        return 0;

    /* length */
    outer_length = asn1_length(px, length, &offset);
    if (length > outer_length + offset)
        length = (size_t)(outer_length + offset);

    /* Version */
    version = asn1_integer(px, length, &offset);
    if (version != 0)
        return 0;

    /* Community */
    if (asn1_tag(px, length, &offset) != 0x04)
        return 0;
    offset += asn1_length(px, length, &offset);

    /* PDU */
    tag = asn1_tag(px, length, &offset);
    if (tag < 0xA0 || 0xA5 < tag)
        return 0;
    outer_length = asn1_length(px, length, &offset);
    if (length > outer_length + offset)
        length = (size_t)(outer_length + offset);

    /* Request ID */
    asn1_tag(px, length, &offset);
    len = asn1_length(px, length, &offset);
    switch (len) {
        case 0:
            return 0;
        case 1:
            px[offset + 0] = (unsigned char)(seqno >> 0) & 0x7F;
            return seqno & 0x7F;
        case 2:
            px[offset + 0] = (unsigned char)(seqno >> 8) & 0x7F;
            px[offset + 1] = (unsigned char)(seqno >> 0);
            return seqno & 0x7fff;
        case 3:
            px[offset + 0] = (unsigned char)(seqno >> 16) & 0x7F;
            px[offset + 1] = (unsigned char)(seqno >> 8);
            px[offset + 2] = (unsigned char)(seqno >> 0);
            return seqno & 0x7fffFF;
        case 4:
            px[offset + 0] = (unsigned char)(seqno >> 24) & 0x7F;
            px[offset + 1] = (unsigned char)(seqno >> 16);
            px[offset + 2] = (unsigned char)(seqno >> 8);
            px[offset + 3] = (unsigned char)(seqno >> 0);
            return seqno & 0x7fffFFFF;
        case 5:
            px[offset + 0] = 0;
            px[offset + 1] = (unsigned char)(seqno >> 24);
            px[offset + 2] = (unsigned char)(seqno >> 16);
            px[offset + 3] = (unsigned char)(seqno >> 8);
            px[offset + 4] = (unsigned char)(seqno >> 0);
            return seqno & 0xffffFFFF;
    }
    return 0;
}

#define TWO_BYTE   ((unsigned long long)(~0) << 7)
#define THREE_BYTE ((unsigned long long)(~0) << 14)
#define FOUR_BYTE  ((unsigned long long)(~0) << 21)
#define FIVE_BYTE  ((unsigned long long)(~0) << 28)

/****************************************************************************
 ****************************************************************************/
static unsigned id_prefix_count(unsigned id) {
    if (id & FIVE_BYTE)
        return 4;
    if (id & FOUR_BYTE)
        return 3;
    if (id & THREE_BYTE)
        return 2;
    if (id & TWO_BYTE)
        return 1;
    return 0;
}

/****************************************************************************
 * Convert text OID to binary
 ****************************************************************************/
static unsigned convert_oid(unsigned char *dst, size_t sizeof_dst,
                            const char *src) {
    size_t offset = 0;

    while (*src) {
        const char *next_src;
        unsigned    id;
        unsigned    count;
        unsigned    i;

        while (*src == '.')
            src++;

        id = (unsigned)strtoul(src, (char **)&next_src, 0);
        if (src == next_src)
            break;
        else
            src = next_src;

        count = id_prefix_count(id);
        for (i = count; i > 0; i--) {
            if (offset < sizeof_dst)
                dst[offset++] = ((id >> (7 * i)) & 0x7F) | 0x80;
        }
        if (offset < sizeof_dst)
            dst[offset++] = (id & 0x7F);
    }

    return (unsigned)offset;
}

/****************************************************************************
 * We need to initialize the OID/MIB parser
 * This should be called on program startup.
 * This is so that we can show short names, like "sysName", rather than
 * the entire OID.
 ****************************************************************************/

static bool snmp_init(const XConf *xconf) {
    snmp_conf.mib_count = xconf->rx_handler_count;
    snmp_conf.global_mibs =
        MALLOC(sizeof(struct SMACK *) * xconf->rx_handler_count);

    for (unsigned i = 0; i < snmp_conf.mib_count; i++) {
        snmp_conf.global_mibs[i] = smack_create("snmp-mib", 0);

        for (unsigned j = 0; mib[j].name; j++) {
            unsigned char pattern[256];
            unsigned      len;

            len = convert_oid(pattern, sizeof(pattern), mib[j].oid);
            smack_add_pattern(snmp_conf.global_mibs[i], pattern, len, j,
                              SMACK_ANCHOR_BEGIN | SMACK_SNMP_HACK);
        }

        smack_compile(snmp_conf.global_mibs[i]);
    }

    return true;
}

static size_t snmp_make_payload(ProbeTarget   *target,
                                unsigned char *payload_buf) {
    memcpy(payload_buf, default_snmp_req, sizeof(default_snmp_req));
    snmp_set_cookie(payload_buf, sizeof(default_snmp_req), target->cookie);

    return sizeof(default_snmp_req);
}

/****************************************************************************
 * Handles an SNMP response.
 ****************************************************************************/
static unsigned snmp_handle_response(unsigned th_idx, ProbeTarget *target,
                                     const unsigned char *px,
                                     unsigned sizeof_px, OutItem *item) {
    unsigned      request_id = 0;
    uint64_t      length     = sizeof_px;
    struct SMACK *global_mib = snmp_conf.global_mibs[th_idx];

    /**
     * Parse SNMP
     * TODO: only SNMPv0 is supported, the parser will have to be extended for
     * newer SNMP.
     * */
    uint64_t    outer_length;
    uint64_t    offset  = 0;
    struct SNMP snmp[1] = {{0}};

    /* tag */
    if (asn1_tag(px, length, &offset) != 0x30)
        goto error;

    /* length */
    outer_length = asn1_length(px, length, &offset);
    if (length > outer_length + offset)
        length = outer_length + offset;

    /* Version */
    snmp->version = asn1_integer(px, length, &offset);
    if (snmp->version != 0)
        goto error;

    /* Community */
    if (asn1_tag(px, length, &offset) != 0x04)
        goto error;
    snmp->community_length = asn1_length(px, length, &offset);
    snmp->community        = px + offset;
    offset += snmp->community_length;

    /* PDU */
    snmp->pdu_tag = asn1_tag(px, length, &offset);
    if (snmp->pdu_tag < 0xA0 || 0xA5 < snmp->pdu_tag)
        goto error;
    outer_length = asn1_length(px, length, &offset);
    if (length > outer_length + offset)
        length = outer_length + offset;

    /* Request ID */
    snmp->request_id = asn1_integer(px, length, &offset);
    request_id       = (unsigned)snmp->request_id;

    if ((target->cookie & 0x7FFFffff) != request_id)
        goto error;

    snmp->error_status = asn1_integer(px, length, &offset);
    snmp->error_index  = asn1_integer(px, length, &offset);

    /* Varbind List */
    if (asn1_tag(px, length, &offset) != 0x30)
        goto error;
    outer_length = asn1_length(px, length, &offset);
    if (length > outer_length + offset)
        length = outer_length + offset;

    /* Var-bind list */
    while (offset < length) {
        uint64_t varbind_length;
        uint64_t varbind_end;
        if (px[offset++] != 0x30) {
            break;
        }
        varbind_length = asn1_length(px, length, &offset);
        if (varbind_length == 0xFFFFffff)
            break;
        varbind_end = offset + varbind_length;
        if (varbind_end > length) {
            break;
        }

        /* OID */
        if (asn1_tag(px, length, &offset) != 6)
            break;
        else {
            uint64_t             oid_length = asn1_length(px, length, &offset);
            const unsigned char *oid        = px + offset;
            uint64_t             var_tag;
            uint64_t             var_length;
            const unsigned char *var;

            offset += oid_length;
            if (offset > length)
                break;

            var_tag    = asn1_tag(px, length, &offset);
            var_length = asn1_length(px, length, &offset);
            var        = px + offset;

            offset += var_length;
            if (offset > length)
                break;

            if (var_tag == 5)
                continue; /* null */

            snmp_banner(global_mib, oid, (size_t)oid_length, var_tag, var,
                        (size_t)var_length, &item->probe_report);
        }
    }

    item->level = OUT_SUCCESS;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "snmp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");

    return 0;

error:
    item->no_output = 1;
    return 0;
}

static void snmp_close() {
    FREE(snmp_conf.global_mibs);
    snmp_conf.mib_count = 0;
}

Probe SnmpProbe = {
    .name       = "snmp",
    .type       = ProbeType_UDP,
    .params     = NULL,
    .short_desc = "Do SNMP scan and try to get some host info.",
    .desc = "SnmpProbe sends an snmp(v1) request with community `public` and "
            "expects sysName and sysDesc of target. The default snmp(over udp) "
            "port is 161.\n"
            "NOTE: SnmpProbe is capable of obtaining the basic info on snmp(v1"
            " or v2c) theoretically but cannot identifying whether the port is "
            "serving of snmp protocol.",

    .init_cb              = &snmp_init,
    .make_payload_cb      = &snmp_make_payload,
    .validate_response_cb = &probe_all_response_valid,
    .handle_response_cb   = &snmp_handle_response,
    .close_cb             = &snmp_close,
};