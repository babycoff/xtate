#include "proto-dns.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef _WIN32
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "../util-misc/misc.h"
#include "../util-data/safe-string.h"

static char *hexchars = "0123456789abcdef";

const size_t DNS_PACKET_MINIMUM_SIZE = 17; // as we handle them
// 12 bytes header + 1 byte question name + 2 bytes question class + 2 bytes
// question type

dns_record_type dns_str_to_record_type(const char *str) {
    // Performance is important here because we may want to use this when
    // reading large numbers of DNS queries from a file.
    long int code;
    char    *endptr;

    switch (tolower(str[0])) {
        case 'a':
            switch (tolower(str[1])) {
                case 0:
                    return DNS_REC_A;
                case 'a':
                    if (tolower(str[2]) == 'a' && tolower(str[3]) == 'a' &&
                        str[4] == 0) {
                        return DNS_REC_AAAA;
                    }
                    return DNS_REC_INVALID;
                case 'f':
                    if (tolower(str[2]) == 's' && tolower(str[3]) == 'd' &&
                        tolower(str[4]) == 'b' && str[5] == 0) {
                        return DNS_REC_AFSDB;
                    }
                    return DNS_REC_INVALID;
                case 'n':
                    if (tolower(str[2]) == 'y' && str[3] == 0) {
                        return DNS_REC_ANY;
                    }
                    return DNS_REC_INVALID;
                case 'p':
                    if (tolower(str[2]) == 'l' && str[3] == 0) {
                        return DNS_REC_APL;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'c':
            switch (tolower(str[1])) {
                case 'a':
                    if (tolower(str[2]) == 'a' && str[3] == 0) {
                        return DNS_REC_CAA;
                    }
                    return DNS_REC_INVALID;
                case 'd':
                    switch (tolower(str[2])) {
                        case 's':
                            if (str[3] == 0) {
                                return DNS_REC_CDS;
                            }
                            return DNS_REC_INVALID;
                        case 'n':
                            if (tolower(str[3]) == 's' &&
                                tolower(str[4]) == 'k' &&
                                tolower(str[5]) == 'e' &&
                                tolower(str[6]) == 'y' && str[7] == 0) {
                                return DNS_REC_CDNSKEY;
                            }
                            return DNS_REC_INVALID;
                        default:
                            return DNS_REC_INVALID;
                    }
                case 'e':
                    if (tolower(str[2]) == 'r' && tolower(str[3]) == 't' &&
                        str[4] == 0) {
                        return DNS_REC_CERT;
                    }
                    return DNS_REC_INVALID;
                case 'n':
                    if (tolower(str[2]) == 'a' && tolower(str[3]) == 'm' &&
                        tolower(str[4]) == 'e' && str[5] == 0) {
                        return DNS_REC_CNAME;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'd':
            switch (tolower(str[1])) {
                case 'h':
                    if (tolower(str[2]) == 'c' && tolower(str[3]) == 'i' &&
                        tolower(str[4]) == 'd' && str[5] == 0) {
                        return DNS_REC_DHCID;
                    }
                    return DNS_REC_INVALID;
                case 'l':
                    if (tolower(str[2]) == 'v' && str[3] == 0) {
                        return DNS_REC_DLV;
                    }
                    return DNS_REC_INVALID;
                case 'n':
                    switch (tolower(str[2])) {
                        case 'a':
                            if (tolower(str[3]) == 'm' &&
                                tolower(str[4]) == 'e' && str[5] == 0) {
                                return DNS_REC_DNAME;
                            }
                            return DNS_REC_INVALID;
                        case 's':
                            if (tolower(str[3]) == 'k' &&
                                tolower(str[4]) == 'e' &&
                                tolower(str[5]) == 'y' && str[6] == 0) {
                                return DNS_REC_DNSKEY;
                            }
                            return DNS_REC_INVALID;
                        default:
                            return DNS_REC_INVALID;
                    }
                case 's':
                    if (str[2] == 0) {
                        return DNS_REC_DS;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'h':
            switch (tolower(str[1])) {
                case 'i':
                    if (tolower(str[2]) == 'p' && str[3] == 0) {
                        return DNS_REC_HIP;
                    }
                    return DNS_REC_INVALID;
                case 't':
                    if (tolower(str[2]) == 't' && tolower(str[3]) == 'p' &&
                        tolower(str[4]) == 's' && str[5] == 0) {
                        return DNS_REC_HTTPS;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'i':
            if (tolower(str[1]) == 'p' && tolower(str[2]) == 's' &&
                tolower(str[3]) == 'e' && tolower(str[4]) == 'c' &&
                tolower(str[5]) == 'k' && tolower(str[6]) == 'e' &&
                tolower(str[7]) == 'y' && str[8] == 0) {
                return DNS_REC_IPSECKEY;
            }
            return DNS_REC_INVALID;
        case 'k':
            switch (tolower(str[1])) {
                case 'e':
                    if (tolower(str[2]) == 'y' && str[3] == 0) {
                        return DNS_REC_KEY;
                    }
                    return DNS_REC_INVALID;
                case 'x':
                    if (str[2] == 0) {
                        return DNS_REC_KX;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'l':
            if (tolower(str[1]) == 'o' && tolower(str[2]) == 'c' &&
                str[3] == 0) {
                return DNS_REC_LOC;
            }
            return DNS_REC_INVALID;
        case 'm':
            if (tolower(str[1]) == 'x' && str[2] == 0) {
                return DNS_REC_MX;
            }
            return DNS_REC_INVALID;
        case 'n':
            switch (tolower(str[1])) {
                case 'a':
                    if (tolower(str[2]) == 'p' && tolower(str[3]) == 't' &&
                        tolower(str[4]) == 'r' && str[5] == 0) {
                        return DNS_REC_NAPTR;
                    }
                    return DNS_REC_INVALID;
                case 's':
                    switch (tolower(str[2])) {
                        case 0:
                            return DNS_REC_NS;
                        case 'e':
                            if (tolower(str[3]) == 'c') {
                                switch (tolower(str[4])) {
                                    case 0:
                                        return DNS_REC_NSEC;
                                    case '3':
                                        if (str[5] == 0) {
                                            return DNS_REC_NSEC3;
                                        }
                                        if (tolower(str[5]) == 'p' &&
                                            tolower(str[6]) == 'a' &&
                                            tolower(str[7]) == 'r' &&
                                            tolower(str[8]) == 'a' &&
                                            tolower(str[9]) == 'm' &&
                                            str[10] == 0) {
                                            return DNS_REC_NSEC3PARAM;
                                        }
                                        return DNS_REC_INVALID;
                                    default:
                                        return DNS_REC_INVALID;
                                }
                            }
                            return DNS_REC_INVALID;
                        default:
                            return DNS_REC_INVALID;
                    }
                default:
                    return DNS_REC_INVALID;
            }
        case 'o':
            if (tolower(str[1]) == 'p' && tolower(str[2]) == 'e' &&
                tolower(str[3]) == 'n' && tolower(str[4]) == 'p' &&
                tolower(str[5]) == 'g' && tolower(str[6]) == 'p' &&
                tolower(str[7]) == 'k' && tolower(str[8]) == 'e' &&
                tolower(str[9]) == 'y' && str[10] == 0) {
                return DNS_REC_OPENPGPKEY;
            }
            return DNS_REC_INVALID;
        case 'p':
            if (tolower(str[1]) == 't' && tolower(str[2]) == 'r' &&
                str[3] == 0) {
                return DNS_REC_PTR;
            }
            return DNS_REC_INVALID;
        case 'r':
            switch (tolower(str[1])) {
                case 'p':
                    if (str[2] == 0) {
                        return DNS_REC_RP;
                    }
                    return DNS_REC_INVALID;
                case 'r':
                    if (tolower(str[2]) == 's' && tolower(str[3]) == 'i' &&
                        tolower(str[4]) == 'g' && str[5] == 0) {
                        return DNS_REC_RRSIG;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 's':
            switch (tolower(str[1])) {
                case 'i':
                    if (tolower(str[2]) == 'g' && tolower(str[3]) == 0) {
                        return DNS_REC_SIG;
                    }
                    return DNS_REC_INVALID;
                case 'm':
                    if (tolower(str[2]) == 'i' && tolower(str[3]) == 'm' &&
                        tolower(str[4]) == 'e' && tolower(str[5]) == 'a' &&
                        str[6] == 0) {
                        return DNS_REC_SMIMEA;
                    }
                    return DNS_REC_INVALID;
                case 'o':
                    if (tolower(str[2]) == 'a' && tolower(str[3]) == 0) {
                        return DNS_REC_SOA;
                    }
                    return DNS_REC_INVALID;
                case 'r':
                    if (tolower(str[2]) == 'v' && tolower(str[3]) == 0) {
                        return DNS_REC_SRV;
                    }
                    return DNS_REC_INVALID;
                case 's':
                    if (tolower(str[2]) == 'h' && tolower(str[3]) == 'f' &&
                        tolower(str[4]) == 'p' && str[5] == 0) {
                        return DNS_REC_SSHFP;
                    }
                    return DNS_REC_INVALID;
                case 'v':
                    if (tolower(str[2]) == 'c' && tolower(str[3]) == 'b' &&
                        str[4] == 0) {
                        return DNS_REC_SVCB;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 't':
            switch (tolower(str[1])) {
                case 'a':
                    if (str[2] == 0) {
                        return DNS_REC_TA;
                    }
                    return DNS_REC_INVALID;
                case 'k':
                    if (tolower(str[2]) == 'e' && tolower(str[3]) == 'y' &&
                        str[4] == 0) {
                        return DNS_REC_TKEY;
                    }
                    return DNS_REC_INVALID;
                case 'l':
                    if (tolower(str[2]) == 's' && tolower(str[3]) == 'a' &&
                        str[4] == 0) {
                        return DNS_REC_TLSA;
                    }
                    return DNS_REC_INVALID;
                case 's':
                    if (tolower(str[2]) == 'i' && tolower(str[3]) == 'g' &&
                        str[4] == 0) {
                        return DNS_REC_TSIG;
                    }
                    return DNS_REC_INVALID;
                case 'x':
                    if (tolower(str[2]) == 't' && str[3] == 0) {
                        return DNS_REC_TXT;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'u':
            switch (tolower(str[1])) {
                case 'r':
                    if (tolower(str[2]) == 'i' && str[3] == 0) {
                        return DNS_REC_URI;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            code = strtol(str, &endptr, 10);
            if (code < 0 || code > 0xFFFF || *endptr != 0) {
                return DNS_REC_INVALID;
            }
            return (dns_record_type)code;
        default:
            return DNS_REC_INVALID;
    }
}

bool dns_str2rcode(char *str, dns_rcode *code) {
    if (strcasecmp(str, "ok") == 0 || strcasecmp(str, "noerror") == 0) {
        *code = DNS_RCODE_NOERROR;
        return true;
    } else if (strcasecmp(str, "formerr") == 0) {
        *code = DNS_RCODE_FORMERR;
        return true;
    } else if (strcasecmp(str, "servfail") == 0) {
        *code = DNS_RCODE_SERVFAIL;
        return true;
    } else if (strcasecmp(str, "nxdomain") == 0) {
        *code = DNS_RCODE_NXDOMAIN;
        return true;
    } else if (strcasecmp(str, "notimp") == 0) {
        *code = DNS_RCODE_NOTIMP;
        return true;
    } else if (strcasecmp(str, "refused") == 0) {
        *code = DNS_RCODE_REFUSED;
        return true;
    } else if (strcasecmp(str, "yxdomain") == 0) {
        *code = DNS_RCODE_YXDOMAIN;
        return true;
    } else if (strcasecmp(str, "yxrrset") == 0) {
        *code = DNS_RCODE_YXRRSET;
        return true;
    } else if (strcasecmp(str, "notauth") == 0) {
        *code = DNS_RCODE_NOTAUTH;
        return true;
    } else if (strcasecmp(str, "notzone") == 0) {
        *code = DNS_RCODE_NOTZONE;
        return true;
    } else if (strcasecmp(str, "badvers") == 0 ||
               strcasecmp(str, "badsig") == 0) {
        *code = DNS_RCODE_BADVERS;
        return true;
    } else if (strcasecmp(str, "badkey") == 0) {
        *code = DNS_RCODE_BADKEY;
        return true;
    } else if (strcasecmp(str, "badtime") == 0) {
        *code = DNS_RCODE_BADTIME;
        return true;
    } else if (strcasecmp(str, "badmode") == 0) {
        *code = DNS_RCODE_BADMODE;
        return true;
    } else if (strcasecmp(str, "badname") == 0) {
        *code = DNS_RCODE_BADNAME;
        return true;
    } else if (strcasecmp(str, "badalg") == 0) {
        *code = DNS_RCODE_BADALG;
        return true;
    } else if (strcasecmp(str, "badtrunc") == 0) {
        *code = DNS_RCODE_BADTRUNC;
        return true;
    } else if (strcasecmp(str, "badcookie") == 0) {
        *code = DNS_RCODE_BADCOOKIE;
        return true;
    } else {
        char         *endptr;
        unsigned long result = strtoul(str, &endptr, 10);
        if (*endptr != 0 || result > UINT16_MAX) {
            return false;
        }
        *code = (dns_rcode)result;
        return true;
    }
    return false;
}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

static inline bool is_valid_label_char(int c) {
    return isalnum(c) || c == '-' || c == '_';
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/**
 * Parse a DNS name from a DNS packet into a buffer.
 *
 * @param begin A pointer to the first byte of the DNS packet.
 * @param buf A pointer to the first byte of the name to be parsed.
 * @param end A pointer to the first byte succeeding the DNS packet.
 * @param name The buffer which the name is read into.
 * @param len Pointer to an integer which is filled with the total length of
 * the name.
 * @param next Will be set to the byte succeeding the first DNS pointer if
 * applicable or the entire DNS name otherwise.
 * @return Whether the name was parsed successfully.
 */
static bool parse_name(uint8_t *begin, uint8_t *buf, const uint8_t *end,
                       uint8_t *name, uint8_t *len, uint8_t **next) {
    int      label_type;
    int      label_len;
    int      name_len = 0;
    uint8_t *pointer  = NULL;

    while (true) {
        if (buf >= end) {
            return false;
        }
        label_type = (*buf & 0xC0);
        if (label_type == 0xC0) // Compressed
        {
            if (end - buf < 2) {
                return false;
            }

            // Set the next parameter if it has not been set yet
            if (next && !pointer) {
                *next = buf + 2;
            }

            // Parse pointer address
            pointer = begin + (htons(*((uint16_t *)buf)) & 0x3FFF);

            // Address must be smaller than the current position
            if (pointer >= buf) {
                return false;
            }

            // Continue parsing at the pointer location.
            buf = pointer;
        } else if (label_type == 0x00) // Uncompressed
        {
            label_len = (*buf & 0x3F) + 1;
            name_len += label_len;
            if (name_len >= 0xFF || end - buf < label_len) {
                return false;
            }
            if (label_len == 1) {
                *name = 0;
                if (next && !pointer) {
                    *next = buf + 1;
                }
                *len = (uint8_t)name_len;
                return true;
            } else {
                memcpy(name, buf, (size_t)label_len);
                name += label_len;
                buf += label_len;
            }
        } else {
            return false;
        }
    }
}

static inline void dns_buffer_set_id(uint8_t *buf, uint16_t id) {
    *((uint16_t *)buf) = htons(id);
}

const char *dns_class2str(dns_class cls) {
    switch (cls) {
        case DNS_CLS_IN:
            return "IN";
        case DNS_CLS_CH:
            return "H";
        case DNS_CLS_HS:
            return "HS";
        case DNS_CLS_QCLASS_NONE:
            return "QNONE";
        case DNS_CLS_QCLASS_ANY:
            return "QANY";
        default:
            return "UNKNOWN";
    }
}

const char *dns_opcode2str(dns_opcode opcode) {
    switch (opcode) {
        case DNS_OPCODE_QUERY:
            return "QUERY";
        case DNS_OPCODE_IQUERY:
            return "IQUERY";
        case DNS_OPCODE_STATUS:
            return "STATUS";
        case DNS_OPCODE_NOTIFY:
            return "NOTIFY";
        case DNS_OPCODE_UPDATE:
            return "UPDATE";
        default:
            return "UNKNOWN";
    }
}

const char *dns_rcode2str(dns_rcode rcode) {
    switch (rcode) {
        case DNS_RCODE_NOERROR:
            return "NOERROR";
        case DNS_RCODE_FORMERR:
            return "FORMERR";
        case DNS_RCODE_SERVFAIL:
            return "SERVFAIL";
        case DNS_RCODE_NXDOMAIN:
            return "NXDOMAIN";
        case DNS_RCODE_NOTIMP:
            return "NOTIMP";
        case DNS_RCODE_REFUSED:
            return "REFUSED";
        case DNS_RCODE_YXDOMAIN:
            return "YXDOMAIN";
        case DNS_RCODE_YXRRSET:
            return "YXRRSET";
        case DNS_RCODE_NOTAUTH:
            return "NOTAUTH";
        case DNS_RCODE_NOTZONE:
            return "NOTZONE";
        case DNS_RCODE_BADVERS:
            return "BADVERS";
        case DNS_RCODE_BADKEY:
            return "BADKEY";
        case DNS_RCODE_BADTIME:
            return "BADTIME";
        case DNS_RCODE_BADMODE:
            return "BADMODE";
        case DNS_RCODE_BADNAME:
            return "BADNAME";
        case DNS_RCODE_BADALG:
            return "BADALG";
        case DNS_RCODE_BADTRUNC:
            return "BADTRUNC";
        case DNS_RCODE_BADCOOKIE:
            return "BADCOOKIE";
        default:
            return "UNKNOWN";
    }
}

const char *dns_record_type2str(dns_record_type type) {
    switch (type) {
        case DNS_REC_A:
            return "A";
        case DNS_REC_AAAA:
            return "AAAA";
        case DNS_REC_AFSDB:
            return "AFSDB";
        case DNS_REC_ANY:
            return "ANY";
        case DNS_REC_APL:
            return "APL";
        case DNS_REC_CAA:
            return "CAA";
        case DNS_REC_CDNSKEY:
            return "CDNSKEY";
        case DNS_REC_CDS:
            return "CDS";
        case DNS_REC_CERT:
            return "CERT";
        case DNS_REC_CNAME:
            return "CNAME";
        case DNS_REC_DHCID:
            return "DHCID";
        case DNS_REC_DLV:
            return "DLV";
        case DNS_REC_DNAME:
            return "DNAME";
        case DNS_REC_DNSKEY:
            return "DNSKEY";
        case DNS_REC_DS:
            return "DS";
        case DNS_REC_HIP:
            return "HIP";
        case DNS_REC_IPSECKEY:
            return "IPSECKEY";
        case DNS_REC_KEY:
            return "KEY";
        case DNS_REC_KX:
            return "KX";
        case DNS_REC_LOC:
            return "LOC";
        case DNS_REC_MX:
            return "MX";
        case DNS_REC_NAPTR:
            return "NAPTR";
        case DNS_REC_NS:
            return "NS";
        case DNS_REC_NSEC:
            return "NSEC";
        case DNS_REC_NSEC3:
            return "NSEC3";
        case DNS_REC_NSEC3PARAM:
            return "NSEC3PARAM";
        case DNS_REC_OPENPGPKEY:
            return "OPENPGPKEY";
        case DNS_REC_PTR:
            return "PTR";
        case DNS_REC_RRSIG:
            return "RRSIG";
        case DNS_REC_RP:
            return "RP";
        case DNS_REC_SIG:
            return "SIG";
        case DNS_REC_SMIMEA:
            return "SMIMEA";
        case DNS_REC_SOA:
            return "SOA";
        case DNS_REC_SRV:
            return "SRV";
        case DNS_REC_SSHFP:
            return "SSHFP";
        case DNS_REC_TA:
            return "TA";
        case DNS_REC_TKEY:
            return "TKEY";
        case DNS_REC_TLSA:
            return "TLSA";
        case DNS_REC_TSIG:
            return "TSIG";
        case DNS_REC_TXT:
            return "TXT";
        case DNS_REC_URI:
            return "URI";
        case DNS_REC_SVCB:
            return "SVCB";
        case DNS_REC_HTTPS:
            return "HTTPS";
        default:
            return "UNKNOWN";
    }
}

int dns_str2namebuf(const char *name, uint8_t *buffer) {
    uint8_t *bufname;
    uint8_t *lenptr;
    uint8_t  total_len;
    uint8_t  label_len;

    lenptr    = buffer;     // points to the byte containing the label length
    bufname   = buffer + 1; // points to the first byte of the actual name
    total_len = 0;
    label_len = 0;

    while (true) {
        char c = *(name++);
        total_len++;
        if (total_len > 254) {
            return -1;
        }
        if (c == '.') {
            *lenptr = label_len;
            if (total_len == 1) {
                total_len--;
                break;
            }
            if (*name == 0) {
                *(bufname++) = 0;
                break;
            }
            if (*name == '.') {
                return -1;
            }
            lenptr    = bufname++;
            label_len = 0;
        } else if (c == 0) {
            *lenptr      = label_len;
            *(bufname++) = 0;
            break;
        } else {
            *(bufname++) = (uint8_t)c;
            label_len++;
            if (label_len >= 64) {
                return -1;
            }
        }
    }
    return total_len + 1;
}

uint16_t dns_question_size(dns_name_t *name) { return name->length + 16; }

uint16_t dns_question_create_from_name(uint8_t *buffer, dns_name_t *name,
                                       dns_record_type type, uint16_t id) {
    uint8_t *aftername;

    dns_buffer_set_id(buffer, id);
    *((uint16_t *)(buffer + 2))  = 0;
    *((uint16_t *)(buffer + 4))  = htons(1);
    *((uint16_t *)(buffer + 6))  = 0;
    *((uint16_t *)(buffer + 8))  = 0;
    *((uint16_t *)(buffer + 10)) = 0;
    memcpy(buffer + 12, name->name, name->length);
    aftername                      = buffer + 12 + name->length;
    *((uint16_t *)aftername)       = htons(type);
    *((uint16_t *)(aftername + 2)) = htons(DNS_CLS_IN);
    return aftername + 4 - buffer;
}

// Requires a buffer of at least 272 bytes to be supplied
int dns_question_create(uint8_t *buffer, char *name, dns_record_type type,
                        uint16_t id) {
    uint8_t *aftername;

    int name_len = dns_str2namebuf(name, buffer + 12);
    if (name_len < 0) {
        return -1;
    }
    aftername = buffer + 12 + name_len;

    dns_buffer_set_id(buffer, id);
    *((uint16_t *)(buffer + 2))    = 0;
    *((uint16_t *)aftername)       = htons(type);
    *((uint16_t *)(aftername + 2)) = htons(DNS_CLS_IN);
    *((uint16_t *)(buffer + 4))    = htons(0x0001);
    return aftername + 4 - buffer;
}

bool dns_send_question(uint8_t *buffer, char *name, dns_record_type type,
                       uint16_t id, int fd, struct sockaddr_storage *addr) {
    int result = dns_question_create(buffer, name, type, id);
    if (result < DNS_PACKET_MINIMUM_SIZE) {
        return false;
    }
    sendto(fd, (void *)buffer, (size_t)result, 0, (struct sockaddr *)addr,
           addr->ss_family == PF_INET ? sizeof(struct sockaddr_in)
                                      : sizeof(struct sockaddr_in6));
    return true;
}

bool dns_parse_question(uint8_t *buf, size_t len, dns_head_t *head,
                        uint8_t **body_begin) {
    uint8_t *end = buf + len; // exclusive
    uint8_t *qname_end = NULL;
    bool     name_parsed;
    if (len < DNS_PACKET_MINIMUM_SIZE) {
        return false;
    }

    head->header.id         = ntohs((*(uint16_t *)buf));
    head->header.qr         = (bool)(buf[2] & 0x80);
    head->header.opcode     = (uint8_t)((buf[2] & (0x78)) >> 3);
    head->header.aa         = (bool)(buf[2] & 0x04);
    head->header.tc         = (bool)(buf[2] & 0x02);
    head->header.rd         = (bool)(buf[2] & 0x01);
    head->header.ra         = (bool)(buf[3] & 0x80);
    head->header.z          = (bool)(buf[4] & 0x40);
    head->header.ad         = (bool)(buf[3] & 0x20);
    head->header.cd         = (bool)(buf[3] & 0x10);
    head->header.rcode      = (uint8_t)(buf[3] & 0x0F);
    head->header.ans_count  = ntohs((*(uint16_t *)(buf + 6)));
    head->header.auth_count = ntohs((*(uint16_t *)(buf + 8)));
    head->header.add_count  = ntohs((*(uint16_t *)(buf + 10)));
    head->header.q_count    = ntohs((*(uint16_t *)(buf + 4)));

    if (head->header.q_count != 1) {
        return false;
    }
    name_parsed = parse_name(buf, buf + 12, end, head->question.name.name,
                             &head->question.name.length, &qname_end);
    if (!name_parsed) {
        return false;
    }
    /* qtype + qclass follow the question name: four bytes in total. */
    if (qname_end + 4 > end) {
        return false;
    }
    head->question.type  = (dns_record_type)ntohs((*(uint16_t *)qname_end));
    head->question.class = ntohs((*(uint16_t *)(qname_end + 2)));
    if (body_begin) {
        *body_begin = qname_end + 4;
    }
    return true;
}

bool dns_names_eq(dns_name_t *name1, dns_name_t *name2) {
    if (name1->length != name2->length) {
        return false;
    }
    uint_fast8_t label_length_offset = 0;
    for (uint_fast8_t i = 0; i < name1->length; i++) {
        if (i == label_length_offset) {
            if (name1->name[i] != name2->name[i]) {
                return false;
            }
            label_length_offset += name1->name[i];
        } else {
            if (tolower(name1->name[i]) != tolower(name2->name[i])) {
                return false;
            }
        }
    }
    return true;
}

bool dns_raw_names_eq(dns_name_t *name1, dns_name_t *name2) {
    return name1->length == name2->length &&
           memcmp(name1->name, name2->name, name1->length) == 0;
}

bool dns_parse_record_raw(uint8_t *begin, uint8_t *buf, const uint8_t *end,
                          uint8_t **next, dns_record_t *record) {
    if (!parse_name(begin, buf, end, record->name.name, &record->name.length,
                    next)) {
        return false;
    }
    if (*next + 10 > end) {
        return false;
    }

    record->type   = ntohs((*(uint16_t *)(*next)));
    record->class  = ntohs((*(uint16_t *)(*next + 2)));
    record->ttl    = ntohl((*(uint32_t *)(*next + 4)));
    record->length = ntohs((*(uint16_t *)(*next + 8)));
    *next          = *next + 10;

    record->data.raw = *next;

    *next = *next + record->length;
    if (*next > end) {
        return false;
    }
    return true;
}

bool dns_parse_record(uint8_t *begin, uint8_t *buf, const uint8_t *end,
                      uint8_t **next, dns_record_t *record) {
    if (!dns_parse_record_raw(begin, buf, end, next, record)) {
        return false;
    }

    if (record->type == DNS_REC_A) {
        if (record->length != 4) {
            return false;
        }
    } else if (record->type == DNS_REC_AAAA) {
        if (record->length != 16) {
            return false;
        }
    } else if (record->type == DNS_REC_NS) {
        if (record->length > 0xFF) {
            return false;
        }
        if (!parse_name(begin, record->data.raw, end, record->data.name.name,
                        &record->data.name.length, NULL)) {
            return false;
        }
    }

    // We don't care about any other records.

    return true;
}

bool dns_parse_body(uint8_t *buf, uint8_t *begin, const uint8_t *end,
                    dns_pkt_t *packet) {
    uint8_t     *next;
    int_fast32_t i;

    next = buf;
    for (i = 0; i < min(packet->head.header.ans_count,
                        ARRAY_SIZE(packet->body.ans) - 1);
         i++) {
        if (!dns_parse_record(begin, next, end, &next, &packet->body.ans[i])) {
            return false;
        }
    }
    packet->body.ans[i].type = 0;
    // Clamp the header count to the number of records actually parsed so that
    // consumers cannot index past the fixed-size body arrays with a malformed
    // (or simply larger-than-array) header count.
    packet->head.header.ans_count = (uint16_t)i;

    for (i = 0; i < min(packet->head.header.auth_count,
                        ARRAY_SIZE(packet->body.auth) - 1);
         i++) {
        if (!dns_parse_record(begin, next, end, &next, &packet->body.auth[i])) {
            return false;
        }
    }
    packet->body.auth[i].type = 0;
    packet->head.header.auth_count = (uint16_t)i;

    for (i = 0; i < min(packet->head.header.add_count,
                        ARRAY_SIZE(packet->body.add) - 1);
         i++) {
        if (!dns_parse_record(begin, next, end, &next, &packet->body.add[i])) {
            return false;
        }
    }
    packet->body.add[i].type = 0;
    packet->head.header.add_count = (uint16_t)i;

    // TODO: Check whether overly long packets are valid. If not, discard them
    // here.

    return true;
}

bool dns_parse_reply(uint8_t *buf, size_t len, dns_pkt_t *packet) {
    uint8_t *body_begin;
    if (!dns_parse_question(buf, len, &packet->head, &body_begin)) {
        return false;
    }
    return dns_parse_body(body_begin, buf, buf + len, packet);
}

void dns_buf_set_qr(uint8_t *buf, bool value) {
    buf[2] &= 0x7F;
    buf[2] |= (value ? 1 : 0) << 7;
}

void dns_buf_set_rd(uint8_t *buf, bool value) {
    buf[2] &= 0xFE;
    buf[2] |= value ? 1 : 0;
}

void dns_buf_set_rcode(uint8_t *buf, uint8_t code) {
    buf[3] &= 0xF0;
    buf[3] |= code;
}

void dns_send_reply(uint8_t *buffer, size_t len, int fd,
                    struct sockaddr_storage *addr) {
    sendto(fd, (void *)buffer, len, 0, (struct sockaddr *)addr,
           addr->ss_family == PF_INET ? sizeof(struct sockaddr_in)
                                      : sizeof(struct sockaddr_in6));
}

bool dns_create_reply(uint8_t *buffer, size_t *len, char *name,
                      dns_record_type type, uint16_t id, dns_rcode code) {
    int result = dns_question_create(buffer, name, type, id);
    if (result < DNS_PACKET_MINIMUM_SIZE) {
        return false;
    }
    *len = (size_t)result;
    dns_buf_set_qr(buffer, true);
    dns_buf_set_rcode(buffer, code);
    return true;
}

size_t dns_print_readable(char **buf, size_t buflen, const uint8_t *source,
                          size_t len, bool is_name) {
    char  *endbuf              = *buf + buflen;
    size_t label_length_offset = 0;

    for (size_t i = 0; i < len; i++) {
        if (i == label_length_offset && is_name) {
            if (endbuf - *buf <= 1) {
                **buf = 0;
                return 0;
            }
            if (i != 0 || len == 1) {
                *((*buf)++) = '.';
            }
            label_length_offset += source[i] + 1;
            continue;
        }
        if (source[i] >= ' ' && source[i] <= '~' && source[i] != '\\' &&
            (source[i] != '.' || (source[i] == '.' && !is_name))) {
            if (endbuf - *buf <= 1) {
                **buf = 0;
                return 0;
            }
            *((*buf)++) = source[i];
        } else {
            if (*buf >= endbuf - 4) {
                **buf = 0;
                return 0;
            }
            *((*buf)++) = '\\';
            *((*buf)++) = 'x';
            char hex1   = (char)((source[i] >> 4) & 0xF);
            char hex2   = (char)(source[i] & 0xF);
            *((*buf)++) = (char)(hex1 + (hex1 < 10 ? '0' : ('a' - 10)));
            *((*buf)++) = (char)(hex2 + (hex2 < 10 ? '0' : ('a' - 10)));
        }
    }
    **buf = 0;
    return buflen - (endbuf - *buf);
}

void dns_name2str(dns_name_t *name, char *buf, size_t buf_len) {
    dns_print_readable(&buf, buf_len, name->name, name->length, true);
}

void dns_question2str(dns_question_t *question, char *buf, size_t len) {
    char sub_buf[0xFF * 4];
    dns_name2str(&question->name, sub_buf, 0xFF * 4);
    snprintf(buf, len, "%s %s %s", sub_buf,
             dns_class2str((dns_class)question->class),
             dns_record_type2str(question->type));
}

size_t dns_raw_record_data2str(dns_record_t *record, uint8_t *begin,
                               uint8_t *end, bool put_quotes, char *buf,
                               size_t buf_len) {
    dns_name_t        name;
    int               written;
    size_t            ret = 0;
    char              tmp_buf[50];

    char *ptr     = buf;
    char *buf_end = buf + buf_len;

/* Append one literal character, keeping room for the terminating NUL. */
#define DNS_PUT_CHAR(ch)                                                       \
    do {                                                                       \
        if (buf_end - ptr > 1) {                                               \
            *(ptr++) = (ch);                                                   \
            ret++;                                                             \
        }                                                                      \
    } while (0)

    switch (record->type) {
        case DNS_REC_NS:
        case DNS_REC_CNAME:
        case DNS_REC_DNAME:
        case DNS_REC_PTR:
            /* dns_parse_record() decodes NS RDATA in place, overwriting the
             * raw pointer kept in the data union.  Only re-parse the RDATA
             * when the pointer still refers to the packet; otherwise print
             * the name that was decoded by the parser. */
            memset(&name, 0, sizeof(name));
            if ((uintptr_t)record->data.raw >= (uintptr_t)begin &&
                (uintptr_t)record->data.raw < (uintptr_t)end) {
                parse_name(begin, record->data.raw, end, name.name,
                           &name.length, NULL);
            } else if (record->type == DNS_REC_NS) {
                name = record->data.name;
            }
            ret += dns_print_readable(&ptr, (size_t)(buf_end - ptr), name.name,
                                      name.length, true);
            break;
        case DNS_REC_MX: {
            size_t avail;
            if (record->length < 3) {
                goto raw;
            }
            avail = (size_t)(buf_end - ptr);
            if (avail < 2) {
                break;
            }
            memset(&name, 0, sizeof(name));
            written = snprintf(ptr, avail, "%" PRIu16 " ",
                               ntohs(*((uint16_t *)record->data.raw)));
            if (written < 0) {
                return 0;
            }
            if ((size_t)written >= avail) {
                ptr = buf_end - 1;
                ret += avail - 1;
                break;
            }
            ptr += written;
            ret += (size_t)written;
            parse_name(begin, record->data.raw + 2, end, name.name,
                       &name.length, NULL);
            ret += dns_print_readable(&ptr, (size_t)(buf_end - ptr), name.name,
                                      name.length, true);
            break;
        }
        case DNS_REC_TXT: {
            uint8_t *record_end = record->data.raw + record->length;
            uint8_t *data_ptr   = record->data.raw;
            while (data_ptr < record_end) {
                uint8_t length = *(data_ptr++);
                if (data_ptr + length <= record_end) {
                    if (put_quotes) {
                        DNS_PUT_CHAR('"');
                    }
                    ret += dns_print_readable(&ptr, (size_t)(buf_end - ptr),
                                              data_ptr, length, false);
                    data_ptr += length;
                    if (put_quotes) {
                        DNS_PUT_CHAR('"');
                        DNS_PUT_CHAR(' ');
                    }
                } else {
                    break;
                }
            }
            if (ptr < buf_end) {
                *ptr = 0;
            }
            break;
        }
        case DNS_REC_SOA: {
            uint8_t *next   = NULL;
            size_t   avail;
            int      no;
            // We have 5 32-bit values plus two names.
            if (record->length < 22) {
                goto raw;
            }

            memset(&name, 0, sizeof(name));
            if (!parse_name(begin, record->data.raw, end, name.name,
                            &name.length, &next) ||
                !next) {
                goto raw;
            }
            ret += dns_print_readable(&ptr, (size_t)(buf_end - ptr), name.name,
                                      name.length, true);
            DNS_PUT_CHAR(' ');

            if (next + 20 >= record->data.raw + record->length) {
                goto raw;
            }
            memset(&name, 0, sizeof(name));
            if (!parse_name(begin, next, end, name.name, &name.length, &next) ||
                !next) {
                goto raw;
            }
            ret += dns_print_readable(&ptr, (size_t)(buf_end - ptr), name.name,
                                      name.length, true);

            DNS_PUT_CHAR(' ');

            if (next + 20 > record->data.raw + record->length) {
                goto raw;
            }

            avail = (size_t)(buf_end - ptr);
            if (avail == 0) {
                break;
            }
            no = snprintf(ptr, avail,
                          "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32
                          " %" PRIu32,
                          (uint32_t)ntohl(*((uint32_t *)next)),
                          (uint32_t)ntohl(*(((uint32_t *)next) + 1)),
                          (uint32_t)ntohl(*(((uint32_t *)next) + 2)),
                          (uint32_t)ntohl(*(((uint32_t *)next) + 3)),
                          (uint32_t)ntohl(*(((uint32_t *)next) + 4)));
            if (no < 0) {
                return 0;
            }
            ret += ((size_t)no >= avail) ? (avail - 1) : (size_t)no;
            break;
        }
        case DNS_REC_A:
            if (record->length != 4) {
                goto raw;
            }
            inet_ntop(AF_INET, record->data.raw, tmp_buf, 50);
            ret += strlen(tmp_buf);
            safe_strcpy(buf, buf_len, tmp_buf);
            break;
        case DNS_REC_AAAA:
            if (record->length != 16) {
                goto raw;
            }
            inet_ntop(AF_INET6, record->data.raw, tmp_buf, 50);
            ret += strlen(tmp_buf);
            safe_strcpy(buf, buf_len, tmp_buf);
            break;
        case DNS_REC_CAA: {
            size_t  avail;
            uint8_t tag_len;
            if (record->length < 2 || record->data.raw[1] < 1 ||
                record->data.raw[1] > 15 ||
                record->data.raw[1] + 2 > record->length) {
                goto raw;
            }
            avail = (size_t)(buf_end - ptr);
            if (avail < 2) {
                break;
            }
            written = snprintf(ptr, avail, "%" PRIu8 " ",
                               (uint8_t)(record->data.raw[0] >> 7));
            if (written < 0) {
                return 0;
            }
            if ((size_t)written >= avail) {
                ptr = buf_end - 1;
                ret += avail - 1;
                break;
            }
            ret += (size_t)written;
            ptr += written;
            dns_print_readable(&ptr, (size_t)(buf_end - ptr),
                               record->data.raw + 2, record->data.raw[1],
                               false);
            DNS_PUT_CHAR(' ');
            DNS_PUT_CHAR('"');
            tag_len = record->data.raw[1];
            ret += dns_print_readable(
                &ptr, (size_t)(buf_end - ptr), record->data.raw + 2 + tag_len,
                (size_t)(record->length - tag_len - 2), false);
            DNS_PUT_CHAR('"');
            if (ptr < buf_end) {
                *ptr = 0;
            }
            break;
        }
        case DNS_REC_SRV: {
            uint16_t prio;
            uint16_t weight;
            uint16_t port;
            size_t   avail;
            if (record->length < 7) {
                goto raw;
            }
            prio   = ntohs(*((uint16_t *)(record->data.raw + 0)));
            weight = ntohs(*((uint16_t *)(record->data.raw + 2)));
            port   = ntohs(*((uint16_t *)(record->data.raw + 4)));
            avail  = (size_t)(buf_end - ptr);
            if (avail < 2) {
                break;
            }
            written = snprintf(ptr, avail, "%" PRIu16 " %" PRIu16 " %" PRIu16 " ",
                               prio, weight, port);
            if (written < 0) {
                return 0;
            }
            if ((size_t)written >= avail) {
                ptr = buf_end - 1;
                ret += avail - 1;
                break;
            }
            ptr += written;
            ret += (size_t)written;
            memset(&name, 0, sizeof(name));
            parse_name(begin, record->data.raw + 6, end, name.name,
                       &name.length, NULL);
            ret += dns_print_readable(&ptr, (size_t)(buf_end - ptr), name.name,
                                      name.length, true);
            break;
        }
        case DNS_REC_SMIMEA:
        case DNS_REC_TLSA:
            if (record->length < 3) {
                goto raw;
            }
            written = snprintf(
                ptr, buf_end - ptr, "%" PRIu8 " %" PRIu8 " %" PRIu8 " ",
                record->data.raw[0], record->data.raw[1], record->data.raw[2]);
            if (written < 0) {
                return 0;
            }
            ptr += written;
            ret += written;

            for (uint16_t i = 3; i < record->length; i++) {
                uint8_t byte = record->data.raw[i];
                // Two hex chars plus the terminating NUL must fit.
                if (buf_end - ptr < 3) {
                    break;
                }
                *(ptr++) = hexchars[byte >> 4];
                ret++;
                *(ptr++) = hexchars[byte & 0xF];
                ret++;
            }
            if (ptr < buf_end) {
                *ptr = 0;
            } else if (buf_end > buf) {
                buf_end[-1] = 0;
            }
            break;
        raw:
        default:
            ret += dns_print_readable(&ptr, (size_t)(buf_end - ptr),
                                      record->data.raw, record->length, false);
            if (ptr < buf_end) {
                *ptr = 0;
            } else if (buf_end > buf) {
                buf_end[-1] = 0;
            }
    }
    return ret;
}

dns_section_t dns_get_section(uint16_t index, dns_header_t *header) {
    if (index < header->ans_count) {
        return DNS_SECTION_ANSWER;
    } else if (index < header->ans_count + header->auth_count) {
        return DNS_SECTION_AUTHORITY;
    } else {
        return DNS_SECTION_ADDITIONAL;
    }
}

char *dns_section2str(dns_section_t section) {
    switch (section) {
        case DNS_SECTION_ANSWER:
            return "ANSWER";
        case DNS_SECTION_ADDITIONAL:
            return "ADDITIONAL";
        case DNS_SECTION_AUTHORITY:
            return "AUTHORITY";
        case DNS_SECTION_QUESTION:
            return "QUESTION";
        default:
            return "UNKNOWN";
    }
}

char *dns_section2str_lower_plural(dns_section_t section) {
    switch (section) {
        case DNS_SECTION_ANSWER:
            return "answers";
        case DNS_SECTION_ADDITIONAL:
            return "additionals";
        case DNS_SECTION_AUTHORITY:
            return "authorities";
        case DNS_SECTION_QUESTION:
            return "questions";
        default:
            return "unknowns";
    }
}

bool dns_in_zone(dns_name_t *name, dns_name_t *zone) {
    return zone->length == 1 // Provided that the label is a FQDN, this is the
                             // root zone containing everything else
           || (zone->length == name->length &&
               strcasecmp((char *)name->name + name->length - zone->length,
                          (char *)zone->name) == 0) ||
           (zone->length < name->length &&
            strcasecmp((char *)name->name + name->length - zone->length,
                       (char *)zone->name) == 0 &&
            *(name->name + name->length - zone->length - 1) == '.');
}

void dns_print_packet(FILE *fp, dns_pkt_t *packet, uint8_t *begin, size_t len,
                      uint8_t *next) {
    char         buf[0xFFFF];
    dns_record_t rec;

    fprintf(fp,
            ";; ->>HEADER<<- opcode: %s, status: %s, id: %" PRIu16 "\n"
            ";; flags: %s%s%s%s%s%s%s; QUERY: %" PRIu16 ", ANSWER: %" PRIu16
            ", AUTHORITY: %" PRIu16 ", ADDITIONAL: %" PRIu16 "\n\n"
            ";; QUESTION SECTION:\n",
            dns_opcode2str((dns_opcode)packet->head.header.opcode),
            dns_rcode2str((dns_rcode)packet->head.header.rcode),
            packet->head.header.id, packet->head.header.qr ? "qr " : "",
            packet->head.header.ad ? "ad " : "",
            packet->head.header.aa ? "aa " : "",
            packet->head.header.rd ? "rd " : "",
            packet->head.header.ra ? "ra " : "",
            packet->head.header.tc ? "tc " : "",
            packet->head.header.cd ? "cd " : "", packet->head.header.q_count,
            packet->head.header.ans_count, packet->head.header.auth_count,
            packet->head.header.add_count);

    dns_question2str(&packet->head.question, buf, sizeof(buf));
    fprintf(fp, "%s\n", buf);

    uint16_t      i       = 0;
    dns_section_t section = DNS_SECTION_QUESTION;
    char          sub_buf1[0xFF * 4];
    char          sub_buf2[0xFFFF0];
    while (dns_parse_record_raw(begin, next, begin + len, &next, &rec)) {
        dns_section_t new_section = dns_get_section(i++, &packet->head.header);
        if (new_section != section) {
            fprintf(fp, "\n;; %s SECTION:\n", dns_section2str(new_section));
            section = new_section;
        }
        dns_name2str(&rec.name, sub_buf1, 0xFF * 4);
        dns_raw_record_data2str(&rec, begin, begin + len, true, sub_buf2,
                                0xFFFF0);
        fprintf(fp, "%s %" PRIu32 " %s %s %s\n", sub_buf1, rec.ttl,
                dns_class2str((dns_class)rec.class),
                dns_record_type2str((dns_record_type)rec.type), sub_buf2);
    }
    fprintf(fp, "\n\n");
}

uint8_t dns_ip_octet2label(uint8_t *dst, uint8_t octet) {
    uint8_t length = octet >= 100 ? 3 : (octet >= 10 ? 2 : 1);
    for (uint8_t i = 0; i < length; i++) {
        uint8_t digit       = octet % 10;
        dst[length - 1 - i] = (char)('0' + digit);
        octet /= 10;
    }
    return length;
}

bool dns_ip2ptr(const char *qname, dns_name_t *name) {
    struct sockaddr_storage ptr_addr_storage;

    if (inet_pton(AF_INET, qname,
                  &((struct sockaddr_in *)&ptr_addr_storage)->sin_addr) == 1) {
        name->length  = 0;
        uint8_t *addr = (uint8_t *)&((struct sockaddr_in *)&ptr_addr_storage)
                            ->sin_addr.s_addr;
#define ipv4b2l(INDEX)                                                         \
    name->name[name->length] =                                                 \
        dns_ip_octet2label(name->name + name->length + 1, addr[(INDEX)]);      \
    name->length += name->name[name->length] + 1;
        ipv4b2l(3);
        ipv4b2l(2);
        ipv4b2l(1);
        ipv4b2l(0);
        name->name[name->length++] = 7;
        name->name[name->length++] = 'i';
        name->name[name->length++] = 'n';
        name->name[name->length++] = '-';
        name->name[name->length++] = 'a';
        name->name[name->length++] = 'd';
        name->name[name->length++] = 'd';
        name->name[name->length++] = 'r';
        name->name[name->length++] = 4;
        name->name[name->length++] = 'a';
        name->name[name->length++] = 'r';
        name->name[name->length++] = 'p';
        name->name[name->length++] = 'a';
        name->name[name->length++] = 0;

        return true;
    } else if (inet_pton(
                   AF_INET6, qname,
                   &((struct sockaddr_in6 *)&ptr_addr_storage)->sin6_addr) ==
               1) {
        uint8_t *addr = (uint8_t *)&((struct sockaddr_in6 *)&ptr_addr_storage)
                            ->sin6_addr.s6_addr;
#define ipv6b2l(INDEX)                                                         \
    name->name[(INDEX) * 4 + 0] = 1;                                           \
    name->name[(INDEX) * 4 + 1] = hexchars[addr[15 - (INDEX)] & 0xF];          \
    name->name[(INDEX) * 4 + 2] = 1;                                           \
    name->name[(INDEX) * 4 + 3] = hexchars[(addr[15 - (INDEX)] >> 4) & 0xF];

        ipv6b2l(0);
        ipv6b2l(1);
        ipv6b2l(2);
        ipv6b2l(3);
        ipv6b2l(4);
        ipv6b2l(5);
        ipv6b2l(6);
        ipv6b2l(7);
        ipv6b2l(8);
        ipv6b2l(9);
        ipv6b2l(10);
        ipv6b2l(11);
        ipv6b2l(12);
        ipv6b2l(13);
        ipv6b2l(14);
        ipv6b2l(15);
        name->name[64] = 3;
        name->name[65] = 'i';
        name->name[66] = 'p';
        name->name[67] = '6';
        name->name[68] = 4;
        name->name[69] = 'a';
        name->name[70] = 'r';
        name->name[71] = 'p';
        name->name[72] = 'a';
        name->name[73] = 0;
        name->length   = 74;
        return true;
    }
    return false;
}
