#ifndef NOT_FOUND_PCRE2

#include "nmap-service.h"
#include "../util-data/file-open.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../xcmd.h"

#include "../target/target.h"
#include "../target/target-rangeport.h"

#include "../util-misc/misc.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

#if defined(_WIN32)
#define strncasecmp _strnicmp
#endif

/*****************************************************************************
 * Translate string name into enumerated type
 *****************************************************************************/
static enum SvcP_RecordType _parse_type(const char *line, size_t *r_offset,
                                        size_t line_length) {
    static const struct {
        const char          *name;
        size_t               length;
        enum SvcP_RecordType type;
    } name_to_types[] = {{"exclude", 7, SvcP_Exclude},
                         {"probe", 5, SvcP_Probe},
                         {"match", 5, SvcP_Match},
                         {"softmatch", 9, SvcP_Softmatch},
                         {"ports", 5, SvcP_Ports},
                         {"sslports", 8, SvcP_Sslports},
                         {"totalwaitms", 11, SvcP_Totalwaitms},
                         {"tcpwrappedms", 12, SvcP_Tcpwrappedms},
                         {"rarity", 6, SvcP_Rarity},
                         {"fallback", 8, SvcP_Fallback},
                         {0, SvcP_Unknown}};

    size_t               i;
    size_t               offset = *r_offset;
    size_t               name_length;
    size_t               name_offset;
    enum SvcP_RecordType result;

    /* find length of command name */
    name_offset = offset;
    while (offset < line_length && !isspace(line[offset]))
        offset++; /* name = all non-space chars until first space */
    name_length = offset - name_offset;
    while (offset < line_length && isspace(line[offset]))
        offset++; /* trim whitespace after name */
    *r_offset = offset;

    /* Lookup the command name */
    for (i = 0; name_to_types[i].name; i++) {
        if (name_length != name_to_types[i].length)
            continue;
        if (strncasecmp(line + name_offset, name_to_types[i].name,
                        name_length) == 0) {
            break;
        }
    }
    result = name_to_types[i].type;

    /* return the type */
    return result;
}

/*****************************************************************************
 *****************************************************************************/
static int _is_hexchar(int c) {
    switch (c) {
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
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return 1;
        default:
            return 0;
    }
}

/*****************************************************************************
 *****************************************************************************/
static unsigned _hexval(int c) {
    switch (c) {
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
            return c - '0';
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            return c - 'a' + 10;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return c - 'A' + 10;
        default:
            return (unsigned)~0;
    }
}

/*****************************************************************************
 *****************************************************************************/
static struct RangeList _parse_ports(struct NmapServiceProbeList *list,
                                     const char *line, size_t offset,
                                     size_t line_length) {
    /* Examples:
        Exclude 53,T:9100,U:30000-40000
        ports 21,43,110,113,199,505,540,1248,5432,30444
        ports 111,4045,32750-32810,38978
        sslports 443
     */
    unsigned         is_error = 0;
    const char      *p;
    struct RangeList ranges = {0};

    UNUSEDPARM(line_length);

    p = rangelist_parse_ports(&ranges, line + offset, &is_error, 0);

    if (is_error) {
        LOG(LEVEL_ERROR, "%s:%u:%u: bad port spec\n", list->filename,
            list->line_number, (unsigned)(p - line));
        rangelist_rm_all(&ranges);
    }

    return ranges;
}

/*****************************************************************************
 *****************************************************************************/
static unsigned _parse_number(struct NmapServiceProbeList *list,
                              const char *line, size_t offset,
                              size_t line_length) {
    /* Examples:
     totalwaitms 6000
     tcpwrappedms 3000
     rarity 6
     */
    unsigned long long number = 0;

    while (offset < line_length && isdigit(line[offset])) {
        number = number * 10;
        number = number + (line[offset] - '0');
        offset++;
        if (number > 0xFFFFFFFFULL) {
            LOG(LEVEL_ERROR, "%s:%u:%u: number out of range\n",
                list->filename, list->line_number, (unsigned)offset);
            number = 0xFFFFFFFFULL;
            while (offset < line_length && isdigit(line[offset]))
                offset++;
            break;
        }
    }
    while (offset < line_length && isspace(line[offset]))
        offset++;

    if (offset != line_length) {
        LOG(LEVEL_ERROR, "%s:%u:%u: unexpected character '%c'\n",
            list->filename, list->line_number, (unsigned)offset,
            isprint(line[offset]) ? line[offset] : '.');
    }

    return number;
}

/*****************************************************************************
 *****************************************************************************/
static char *_parse_name(const char *line, size_t *r_offset,
                         size_t line_length) {
    size_t name_offset = *r_offset;
    size_t name_length;
    char  *result;

    /* grab all characters until first space */
    while (*r_offset < line_length && !isspace(line[*r_offset]))
        (*r_offset)++;
    name_length = *r_offset - name_offset;
    if (name_length == 0)
        return 0;

    /* trim trailing white space */
    while (*r_offset < line_length && isspace(line[*r_offset]))
        (*r_offset)++;

    /* allocate result string */
    result = MALLOC(name_length + 1);
    memcpy(result, line + name_offset, name_length + 1);
    result[name_length] = '\0';

    return result;
}

/*****************************************************************************
 *****************************************************************************/
static struct ServiceProbeFallback *
_parse_fallback(struct NmapServiceProbeList *list, const char *line,
                size_t offset, size_t line_length) {
    /* Examples:
     fallback GetRequest,GenericLines
     */
    struct ServiceProbeFallback *result = 0;

    while (offset < line_length) {
        size_t                        name_offset;
        size_t                        name_length;
        struct ServiceProbeFallback  *fallback;
        struct ServiceProbeFallback **r_fallback;

        /* grab all characters until first space */
        name_offset = offset;
        while (offset < line_length && !isspace(line[offset]) &&
               line[offset] != ',')
            offset++;
        name_length = offset - name_offset;
        while (offset < line_length &&
               (isspace(line[offset]) || line[offset] == ','))
            offset++; /* trim trailing whitespace */
        if (name_length == 0) {
            LOG(LEVEL_ERROR, "%s:%u:%u: name too short\n", list->filename,
                list->line_number, (unsigned)name_offset);
            break;
        }

        /* Allocate a record */
        fallback = CALLOC(1, sizeof(*fallback));

        fallback->name = MALLOC(name_length + 1);
        memcpy(fallback->name, line + name_offset, name_length + 1);
        fallback->name[name_length] = '\0';

        /* append to end of list */
        for (r_fallback = &result; *r_fallback;
             r_fallback = &(*r_fallback)->next)
            ;
        fallback->next = *r_fallback;
        *r_fallback    = fallback;
    }

    return result;
}

/*****************************************************************************
 *****************************************************************************/
static void _parse_probe(struct NmapServiceProbeList *list, const char *line,
                         size_t offset, size_t line_length) {
    /* Examples:
     Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
     Probe UDP DNSStatusRequest q|\0\0\x10\0\0\0\0\0\0\0\0\0|
     Probe TCP NULL q||
     */
    const char              *filename    = list->filename;
    unsigned                 line_number = list->line_number;
    struct NmapServiceProbe *probe;

    /*
     * We have a new 'Probe', so append a blank record to the end of
     * our list
     */
    probe = CALLOC(1, sizeof(*probe));
    if (list->count + 1 >= list->max_slot) {
        list->max_slot = list->max_slot * 2 + 1;
        list->probes   = REALLOCARRAY(
            list->probes, sizeof(struct NmapServiceProbe *), list->max_slot);
    }
    list->probes[list->count++] = probe;

    /*
     * <protocol>
     */
    if (line_length - offset <= 3) {
        LOG(LEVEL_ERROR, "%s:%u:%u: line too short\n", filename, line_number,
            (unsigned)offset);
        goto parse_error;
    }
    if (memcmp(line + offset, "TCP", 3) == 0)
        probe->protocol = IP_PROTO_TCP;
    else if (memcmp(line + offset, "UDP", 3) == 0)
        probe->protocol = IP_PROTO_UDP;
    else {
        LOG(LEVEL_ERROR, "%s:%u:%u: unknown protocol\n", filename, line_number,
            (unsigned)offset);
        goto parse_error;
    }
    offset += 3;
    if (!isspace(line[offset])) {
        LOG(LEVEL_ERROR, "%s:%u:%u: unexpected character\n", filename,
            line_number, (unsigned)offset);
        goto parse_error;
    }
    while (offset < line_length && isspace(line[offset]))
        offset++;

    /*
     * <probename>
     */
    probe->name = _parse_name(line, &offset, line_length);
    if (probe->name == 0) {
        LOG(LEVEL_ERROR, "%s:%u:%u: probename parse error\n", filename,
            line_number, (unsigned)offset);
        goto parse_error;
    }

    /*
     * <probestring>
     *  - must start with a 'q' character
     *  - a delimiter character starts/stop the string, typically '|'
     *  - Traditional C-style escapes work:
     *      \\ \0, \a, \b, \f, \n, \r, \t, \v, and \xXX
     */
    {
        char   delimiter;
        char  *x;
        size_t x_offset;

        if (line_length - offset <= 2) {
            LOG(LEVEL_ERROR, "%s:%u:%u: line too short\n", filename,
                line_number, (unsigned)offset);
            goto parse_error;
        }
        if (line[offset++] != 'q') {
            LOG(LEVEL_ERROR, "%s:%u:%u: expected 'q', found '%c'\n", filename,
                line_number, (unsigned)offset,
                isprint(line[offset - 1]) ? line[offset - 1] : '.');
            goto parse_error;
        }

        /* The next character is a 'delimiter' that starts and stops the next
         * string of characters, it it usually '|' but may be anything, like
         * '/', as long as the delimiter itself is not contained inside the
         * string */
        delimiter = line[offset++];

        /* allocate a buffer at least as long as the remainder of the line. This
         * is probably too large, but cannot be too small. It's okay if we waste
         * a few characters. */
        x                  = CALLOC(1, line_length - offset + 1);
        probe->hellostring = x;

        /* Grab all the characters until the next delimiter, translating escaped
         * characters as needed */
        x_offset = 0;
        while (offset < line_length && line[offset] != delimiter) {
            /* Normal case: unescaped characters */
            if (line[offset] != '\\') {
                x[x_offset++] = line[offset++];
                continue;
            }

            /* skip escape character '\\' */
            offset++;
            if (offset >= line_length || line[offset] == delimiter) {
                LOG(LEVEL_ERROR, "%s:%u:%u: premature end of field\n", filename,
                    line_number, (unsigned)offset);
                goto parse_error;
            }

            /* Handled escape sequence */
            switch (line[offset++]) {
                default:
                    LOG(LEVEL_ERROR, "%s:%u: %.*s\n", filename, line_number,
                        (unsigned)line_length, line);
                    LOG(LEVEL_ERROR,
                        "%s:%u:%u: unexpected escape character '%c'\n",
                        filename, line_number, (unsigned)offset - 1,
                        isprint(line[offset - 1]) ? line[offset - 1] : '.');
                    goto parse_error;
                case '\\':
                    x[x_offset++] = '\\';
                    break;
                case '0':
                    x[x_offset++] = '\0';
                    break;
                case 'a':
                    x[x_offset++] = '\a';
                    break;
                case 'b':
                    x[x_offset++] = '\b';
                    break;
                case 'f':
                    x[x_offset++] = '\f';
                    break;
                case 'n':
                    x[x_offset++] = '\n';
                    break;
                case 'r':
                    x[x_offset++] = '\r';
                    break;
                case 't':
                    x[x_offset++] = '\t';
                    break;
                case 'v':
                    x[x_offset++] = '\v';
                    break;
                case 'x':
                    /* make sure at least 2 characters exist in input, either
                     * due to line-length or the delimiter */
                    if (offset + 2 >= line_length ||
                        line[offset + 0] == delimiter ||
                        line[offset + 1] == delimiter) {
                        LOG(LEVEL_ERROR, "%s:%u:%u: line too short\n", filename,
                            line_number, (unsigned)offset);
                        goto parse_error;
                    }

                    /* make sure those two characters are hex digits */
                    if (!_is_hexchar(line[offset + 0]) ||
                        !_is_hexchar(line[offset + 1])) {
                        LOG(LEVEL_ERROR,
                            "%s:%u:%u: expected hex, found '%c%c'\n", filename,
                            line_number, (unsigned)offset,
                            isprint(line[offset + 1]) ? line[offset + 1] : '.',
                            isprint(line[offset + 2]) ? line[offset + 2] : '.');
                        goto parse_error;
                    }

                    /* parse those two hex digits */
                    x[x_offset++] = (char)(_hexval(line[offset + 0]) << 4 |
                                           _hexval(line[offset + 1]));
                    offset += 2;
                    break;
            }
        }
        probe->hellolength = x_offset;

        if (offset >= line_length || line[offset] != delimiter) {
            LOG(LEVEL_ERROR, "%s:%u:%u: missing end delimiter '%c'\n", filename,
                line_number, (unsigned)offset,
                isprint(delimiter) ? delimiter : '.');
            goto parse_error;
        }
        // offset++;
    }

    return;

parse_error:
    FREE(probe->name);
    FREE(probe->hellostring);
    FREE(probe);
    list->count--;
}

/*****************************************************************************
 *****************************************************************************/
static struct ServiceProbeMatch *_parse_match(struct NmapServiceProbeList *list,
                                              const char *line, size_t offset,
                                              size_t line_length) {
    /* Examples:
     match ftp m/^220.*Welcome to .*Pure-?FTPd (\d\S+\s*)/ p/Pure-FTPd/ v/$1/
     cpe:/a:pureftpd:pure-ftpd:$1/ match ssh
     m/^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)\r?\n/i p/OpenSSH/ v/$2/ i/protocol $1/
     cpe:/a:openbsd:openssh:$2/ match mysql m|^\x10\0\0\x01\xff\x13\x04Bad
     handshake$| p/MySQL/ cpe:/a:mysql:mysql/ match chargen
     m|@ABCDEFGHIJKLMNOPQRSTUVWXYZ| match uucp m|^login: login: login: $|
     p/NetBSD uucpd/ o/NetBSD/ cpe:/o:netbsd:netbsd/a match printer
     m|^([\w-_.]+): lpd: Illegal service request\n$| p/lpd/ h/$1/ match afs
     m|^[\d\D]{28}\s*(OpenAFS)([\d\.]{3}[^\s\0]*)\0| p/$1/ v/$2/
     */
    const char               *filename    = list->filename;
    unsigned                  line_number = list->line_number;
    struct ServiceProbeMatch *match;

    match = CALLOC(1, sizeof(*match));

    /*
     * <servicename>
     */
    match->service = _parse_name(line, &offset, line_length);
    if (match->service == 0) {
        LOG(LEVEL_ERROR, "%s:%u:%u: servicename is empty\n", filename,
            line_number, (unsigned)offset);
        goto parse_error;
    }

    match->line = line_number;

    /*
     * <pattern>
     *  - must start with a 'm' character
     *  - a delimiter character starts/stop the string, typically '/' or '|'
     *  - contents are PCRE regex
     */
    {
        char   delimiter;
        size_t regex_offset;
        size_t regex_length;

        /* line must start with 'm' */
        if (line_length - offset <= 2) {
            LOG(LEVEL_ERROR, "%s:%u:%u: line too short\n", filename,
                line_number, (unsigned)offset);
            goto parse_error;
        }
        if (line[offset] != 'm') {
            LOG(LEVEL_ERROR, "%s:%u:%u: expected 'm', found '%c'\n", filename,
                line_number, (unsigned)offset,
                isprint(line[offset]) ? line[offset] : '.');
            goto parse_error;
        }
        offset++;

        /* next character is the delimiter */
        delimiter = line[offset++];

        /* Find the length of the regex */
        regex_offset = offset;
        while (offset < line_length && line[offset] != delimiter)
            offset++;
        regex_length = offset - regex_offset;
        if (offset >= line_length || line[offset] != delimiter) {
            LOG(LEVEL_ERROR, "%s:%u:%u: missing ending delimiter '%c'\n",
                filename, line_number, (unsigned)offset,
                isprint(delimiter) ? delimiter : '.');
            goto parse_error;
        } else
            offset++;

        /* add regex pattern to record */
        match->regex_length = regex_length;
        match->regex        = MALLOC(regex_length + 1);
        memcpy(match->regex, line + regex_offset, regex_length + 1);
        match->regex[regex_length] = '\0';

        /* Verify the regex options characters */
        while (offset < line_length && !isspace(line[offset])) {
            switch (line[offset]) {
                case 'i':
                    match->is_case_insensitive = 1;
                    break;
                case 's':
                    match->is_include_newlines = 1;
                    break;
                default:
                    LOG(LEVEL_ERROR,
                        "%s:%u:%u: unknown regex pattern option '%c'\n",
                        filename, line_number, (unsigned)offset,
                        isprint(line[offset]) ? line[offset] : '.');
                    goto parse_error;
            }
            offset++;
        }
        while (offset < line_length && isspace(line[offset]))
            offset++;
    }

    /*
     * <versioninfo>
     *  - several optional fields
     *  - each file starts with identifier (p v i h o d cpe:)
     *  - next comes the delimiter character (preferably '/' slash)
     *  - next comes data
     *  - ends with delimiter
     */
    while (offset < line_length) {
        char               id;
        char               delimiter;
        size_t             value_length;
        size_t             value_offset;
        int                is_a = 0;
        enum SvcV_InfoType type;

        /* Make sure we have enough characters for a versioninfo string */
        if (offset >= line_length)
            break;
        if (offset + 2 >= line_length) {
            LOG(LEVEL_ERROR,
                "%s:%u:%u: unexpected character at end of line '%c'\n",
                filename, line_number, (unsigned)offset,
                isprint(line[offset]) ? line[offset] : '.');
            goto parse_error;
        }

        /* grab the 'id' character, which is either singe letter or the string
         * 'cpe:' */
        id = line[offset++];
        if (id == 'c') {
            if (offset + 3 >= line_length) {
                LOG(LEVEL_ERROR,
                    "%s:%u:%u: unexpected character at end of line '%c'\n",
                    filename, line_number, (unsigned)offset,
                    isprint(line[offset]) ? line[offset] : '.');
                goto parse_error;
            }
            if (memcmp(line + offset, "pe:", 3) != 0) {
                LOG(LEVEL_ERROR, "%s:%u:%u: expected string 'cpe:'\n", filename,
                    line_number, (unsigned)offset);
                goto parse_error;
            }
            offset += 3;
        }
        switch (id) {
            case 'p':
                type = SvcV_ProductName;
                break;
            case 'v':
                type = SvcV_Version;
                break;
            case 'i':
                type = SvcV_Info;
                break;
            case 'h':
                type = SvcV_Hostname;
                break;
            case 'o':
                type = SvcV_OperatingSystem;
                break;
            case 'd':
                type = SvcV_DeviceType;
                break;
            case 'c':
                type = SvcV_CpeName;
                break;
            default:
                LOG(LEVEL_ERROR,
                    "%s:%u:%u: versioninfo unknown identifier '%c'\n", filename,
                    line_number, (unsigned)offset, isprint(id) ? id : '.');
                goto parse_error;
        }

        /* grab the delimiter */
        if (offset + 2 >= line_length) {
            LOG(LEVEL_ERROR, "%s:%u:%u: line too short\n", filename,
                line_number, (unsigned)offset);
            goto parse_error;
        }
        delimiter = line[offset++];

        /* Grab the contents of this string */
        value_offset = offset;
        while (offset < line_length && line[offset] != delimiter)
            offset++;
        value_length = offset - value_offset;
        if (offset >= line_length || line[offset] != delimiter) {
            LOG(LEVEL_ERROR, "%s:%u:%u: missing ending delimiter '%c'\n",
                filename, line_number, (unsigned)offset,
                isprint(delimiter) ? delimiter : '.');
            goto parse_error;
        } else
            offset++;
        if (id == 'c' && offset + 1 <= line_length && line[offset] == 'a') {
            is_a = 1;
            offset++;
        }
        if (offset < line_length && !isspace(line[offset])) {
            LOG(LEVEL_ERROR,
                "%s:%u:%u: unexpected character after delimiter '%c'\n",
                filename, line_number, (unsigned)offset,
                isprint(delimiter) ? delimiter : '.');
            goto parse_error;
        }
        while (offset < line_length && isspace(line[offset]))
            offset++;

        /* Create a versioninfo record */
        {
            struct ServiceVersionInfo  *v;
            struct ServiceVersionInfo **r_v;

            v        = CALLOC(1, sizeof(*v));
            v->type  = type;
            v->value = MALLOC(value_length + 1);
            memcpy(v->value, line + value_offset, value_length + 1);
            v->value[value_length] = '\0';
            v->is_a                = is_a;

            /* insert at end of list */
            for (r_v = &match->versioninfo; *r_v; r_v = &(*r_v)->next)
                ;
            v->next = *r_v;
            *r_v    = v;
        }
    }

    return match;

parse_error:
    FREE(match->regex);
    FREE(match->service);
    while (match->versioninfo) {
        struct ServiceVersionInfo *v = match->versioninfo;
        match->versioninfo           = v->next;
        FREE(v->value);
        FREE(v);
    }
    FREE(match);
    return 0;
}

/*****************************************************************************
 *****************************************************************************/
static void _parse_line(struct NmapServiceProbeList *list, const char *line) {
    const char              *filename    = list->filename;
    unsigned                 line_number = list->line_number;
    size_t                   line_length;
    size_t                   offset;
    enum SvcP_RecordType     type;
    struct RangeList         ranges = {0};
    struct NmapServiceProbe *probe;

    /* trim whitespace */
    offset      = 0;
    line_length = strlen(line);
    while (offset < line_length && isspace(line[offset]))
        offset++;
    while (line_length && isspace(line[line_length - 1]))
        line_length--;

    /* Ignore comment lines */
    if (ispunct(line[offset]))
        return;

    /* Ignore empty lines */
    if (offset >= line_length)
        return;

    /* parse the type field field */
    type = _parse_type(line, &offset, line_length);

    /* parse the remainder of the line, depending upon the type */
    switch ((int)type) {
        case SvcP_Unknown:
            LOG(LEVEL_ERROR, "%s:%u:%u: unknown type: '%.*s'\n", filename,
                line_number, (unsigned)offset, (int)offset - 0, line);
            return;
        case SvcP_Exclude:
            if (list->count) {
                /* The 'Exclude' directive is only valid at the top of the file,
                 * before any Probes */
                LOG(LEVEL_ERROR,
                    "%s:%u:%u: 'Exclude' directive only valid before any "
                    "'Probe'\n",
                    filename, line_number, (unsigned)offset);
            } else {
                ranges = _parse_ports(list, line, offset, line_length);
                if (ranges.list_len == 0) {
                    LOG(LEVEL_ERROR, "%s:%u:%u: 'Exclude' bad format\n",
                        filename, line_number, (unsigned)offset);
                } else {
                    rangelist_merge(&list->exclude, &ranges);
                    rangelist_rm_all(&ranges);
                }
            }
            return;
        case SvcP_Probe:
            /* Creates a new probe record, all the other types (except
             * 'Exclude') operate on the current probe record */
            _parse_probe(list, line, offset, line_length);
            return;
    }

    /*
     * The remaining items only work in the context of the current 'Probe'
     * directive
     */
    if (list->count == 0) {
        LOG(LEVEL_ERROR, "%s:%u:%u: 'directive only valid after a 'Probe'\n",
            filename, line_number, (unsigned)offset);
        return;
    }
    probe = list->probes[list->count - 1];

    switch ((int)type) {
        case SvcP_Ports:
            ranges = _parse_ports(list, line, offset, line_length);
            if (ranges.list_len == 0) {
                LOG(LEVEL_ERROR, "%s:%u:%u: bad ports format\n", filename,
                    line_number, (unsigned)offset);
            } else {
                rangelist_merge(&probe->ports, &ranges);
                rangelist_rm_all(&ranges);
            }
            break;
        case SvcP_Sslports:
            ranges = _parse_ports(list, line, offset, line_length);
            if (ranges.list_len == 0) {
                LOG(LEVEL_ERROR, "%s:%u:%u: bad ports format\n", filename,
                    line_number, (unsigned)offset);
            } else {
                rangelist_merge(&probe->sslports, &ranges);
                rangelist_rm_all(&ranges);
            }
            break;
        case SvcP_Match:
        case SvcP_Softmatch: {
            struct ServiceProbeMatch *match;

            match = _parse_match(list, line, offset, line_length);
            if (match) {
                struct ServiceProbeMatch **r_match;

                /* put at end of list */
                for (r_match = &probe->match; *r_match;
                     r_match = &(*r_match)->next)
                    ;
                match->next         = *r_match;
                *r_match            = match;
                match->is_softmatch = (type == SvcP_Softmatch);
            }
        } break;

        case SvcP_Totalwaitms:
            probe->totalwaitms = _parse_number(list, line, offset, line_length);
            break;
        case SvcP_Tcpwrappedms:
            probe->tcpwrappedms =
                _parse_number(list, line, offset, line_length);
            break;
        case SvcP_Rarity:
            probe->rarity = _parse_number(list, line, offset, line_length);
            break;
        case SvcP_Fallback: {
            struct ServiceProbeFallback *fallback;
            fallback = _parse_fallback(list, line, offset, line_length);
            if (fallback) {
                fallback->next  = probe->fallback;
                probe->fallback = fallback;
            }
        } break;
    }
}

/*****************************************************************************
 *****************************************************************************/
static struct NmapServiceProbeList *
_nmapservice_new_list(const char *filename) {
    struct NmapServiceProbeList *result;

    result           = CALLOC(1, sizeof(*result));
    result->filename = filename;

    return result;
}

/*****************************************************************************
 *****************************************************************************/
struct NmapServiceProbeList *nmapservice_read_file(const char *filename) {
    FILE                        *fp;
    char                         line[32768];
    struct NmapServiceProbeList *result;

    /*
     * Open the file
     */
    fp = file_open_utf8_mode(filename, "rt");
    if (fp == NULL) {
        LOGPERROR(filename);
        return 0;
    }

    /*
     * Create the result structure
     */
    result = _nmapservice_new_list(filename);

    /*
     * parse all lines in the text file
     */
    while (fgets(line, sizeof(line), fp)) {
        /* Track line number for error messages */
        result->line_number++;

        /* A physical line longer than the buffer would otherwise be parsed as
         * several logical lines; drop the remainder and say so. */
        if (!strchr(line, '\n') && !feof(fp)) {
            int ch;
            LOG(LEVEL_WARN, "%s:%u: line too long, truncated\n",
                result->filename, result->line_number);
            while ((ch = fgetc(fp)) != EOF && ch != '\n')
                ;
        }

        /* Parse this string into a record */
        _parse_line(result, line);
    }

    fclose(fp);
    result->filename = 0; /* name no longer valid after this point */
    result->line_number =
        (unsigned)~0; /* line number no longer valid after this point */

    // nmapserviceprobes_print(result, stdout);

    return result;
}

/*****************************************************************************
 *****************************************************************************/
static void nmapserviceprobes_free_record(struct NmapServiceProbe *probe) {
    FREE(probe->name);
    FREE(probe->hellostring);
    rangelist_rm_all(&probe->ports);
    rangelist_rm_all(&probe->sslports);
    while (probe->match) {
        struct ServiceProbeMatch *match = probe->match;
        probe->match                    = match->next;
        FREE(match->regex);
        FREE(match->service);
        while (match->versioninfo) {
            struct ServiceVersionInfo *v = match->versioninfo;
            match->versioninfo           = v->next;
            FREE(v->value);
            FREE(v);
        }
        FREE(match);
    }
    while (probe->fallback) {
        struct ServiceProbeFallback *fallback;

        fallback        = probe->fallback;
        probe->fallback = fallback->next;
        FREE(fallback->name);
        FREE(fallback);
    }

    FREE(probe);
}

/*****************************************************************************
 *****************************************************************************/
static void _nmapservice_print_ports(const struct RangeList *ranges, FILE *fp,
                                     const char *prefix,
                                     unsigned    default_proto) {
    /* don't print anything if no ports */
    if (ranges == NULL || ranges->list_len == 0)
        return;

    /* 'Exclude', 'ports', 'sslports' */
    fprintf(fp, "%s ", prefix);

    rangeport_print(ranges, fp, default_proto);
    fprintf(fp, "\n");
}

/*****************************************************************************
 *****************************************************************************/
static int contains_char(const char *string, size_t length, int c) {
    size_t i;
    for (i = 0; i < length; i++) {
        if (string[i] == c)
            return 1;
    }
    return 0;
}

/*****************************************************************************
 *****************************************************************************/
static void nmapserviceprobes_print_dstring(FILE *fp, const char *string,
                                            size_t length, int delimiter) {
    size_t i;

    /* If the string contains the preferred delimiter, then choose a different
     * delimiter */
    if (contains_char(string, length, delimiter)) {
        static const char *delimiters = "|/\"'#*+-!@$%^&()_=";

        for (i = 0; delimiters[i]; i++) {
            delimiter = delimiters[i];
            if (!contains_char(string, length, delimiter))
                break;
        }
    }

    /* print start delimiter */
    fprintf(fp, "%c", delimiter);

    /* print the string */
    for (i = 0; i < length; i++) {
        char c = string[i];
        fprintf(fp, "%c", c);
    }

    /* print end delimiter */
    fprintf(fp, "%c", delimiter);
}
/*****************************************************************************
 *****************************************************************************/
static void nmapserviceprobes_print_hello(FILE *fp, const char *string,
                                          size_t length, int delimiter) {
    size_t i;

    /* If the string contains the preferred delimiter, then choose a different
     * delimiter */
    if (contains_char(string, length, delimiter)) {
        static const char *delimiters = "|/\"'#*+-!@$%^&()_=";

        for (i = 0; delimiters[i]; i++) {
            delimiter = delimiters[i];
            if (!contains_char(string, length, delimiter))
                break;
        }
    }

    /* print start delimiter */
    fprintf(fp, "%c", delimiter);

    /* print the string */
    for (i = 0; i < length; i++) {
        char c = string[i];

        switch (c) {
            case '\\':
                fprintf(fp, "\\\\");
                break;
            case '\0':
                fprintf(fp, "\\0");
                break;
            case '\a':
                fprintf(fp, "\\a");
                break;
            case '\b':
                fprintf(fp, "\\b");
                break;
            case '\f':
                fprintf(fp, "\\f");
                break;
            case '\n':
                fprintf(fp, "\\n");
                break;
            case '\r':
                fprintf(fp, "\\r");
                break;
            case '\t':
                fprintf(fp, "\\t");
                break;
            case '\v':
                fprintf(fp, "\\v");
                break;
            default:
                if (isprint(c))
                    fprintf(fp, "%c", c);
                else
                    fprintf(fp, "\\x%02x", ((unsigned)c) & 0xFF);
                break;
        }
    }

    /* print end delimiter */
    fprintf(fp, "%c", delimiter);
}

/*****************************************************************************
 *****************************************************************************/
void nmapservice_print_probes(const struct NmapServiceProbeList *list,
                              FILE                              *fp) {
    unsigned i;
    if (list == NULL)
        return;

    _nmapservice_print_ports(&list->exclude, fp, "Exclude", ~0);

    for (i = 0; i < list->count; i++) {
        struct NmapServiceProbe *probe = list->probes[i];

        /* print the first part of the probe */
        fprintf(fp, "Probe %s %s q",
                (probe->protocol == IP_PROTO_TCP) ? "TCP" : "UDP", probe->name);

        /* print the query/hello string */
        nmapserviceprobes_print_hello(fp, probe->hellostring,
                                      probe->hellolength, '|');

        fprintf(fp, "\n");
        if (probe->rarity)
            fprintf(fp, "rarity %u\n", probe->rarity);
        if (probe->totalwaitms)
            fprintf(fp, "totalwaitms %u\n", probe->totalwaitms);
        if (probe->tcpwrappedms)
            fprintf(fp, "tcpwrappedms %u\n", probe->tcpwrappedms);
        _nmapservice_print_ports(&probe->ports, fp, "ports", probe->protocol);
        _nmapservice_print_ports(&probe->sslports, fp, "sslports",
                                 probe->protocol);
        fprintf(fp, "\n");
    }
}

void nmapservice_print_probes_by_file(const char *filename, FILE *fp) {
    if (!filename) {
        LOG(LEVEL_ERROR, "(%s) no nmap-service-probes file specified.\n",
            __func__);
        xcmd_try_reboot();
        exit(1);
    }

    struct NmapServiceProbeList *list = nmapservice_read_file(filename);

    if (!list) {
        LOG(LEVEL_ERROR, "(%s) invalid nmap-service-probes file: %s\n",
            __func__, filename);
        xcmd_try_reboot();
        exit(1);
    }

    if (!list->count) {
        LOG(LEVEL_ERROR, "(%s) no probe has been loaded from %s\n", __func__,
            filename);
        nmapservice_free(list);
        xcmd_try_reboot();
        exit(1);
    }

    nmapservice_print_probes(list, fp);
    nmapservice_free(list);
}

/*****************************************************************************
 *****************************************************************************/
void nmapservice_print_all(const struct NmapServiceProbeList *list, FILE *fp) {
    unsigned i;
    if (list == NULL)
        return;

    _nmapservice_print_ports(&list->exclude, fp, "Exclude", ~0);

    for (i = 0; i < list->count; i++) {
        struct NmapServiceProbe  *probe = list->probes[i];
        struct ServiceProbeMatch *match;

        /* print the first part of the probe */
        fprintf(fp, "Probe %s %s q",
                (probe->protocol == IP_PROTO_TCP) ? "TCP" : "UDP", probe->name);

        /* print the query/hello string */
        nmapserviceprobes_print_hello(fp, probe->hellostring,
                                      probe->hellolength, '|');

        fprintf(fp, "\n");
        if (probe->rarity)
            fprintf(fp, "rarity %u\n", probe->rarity);
        if (probe->totalwaitms)
            fprintf(fp, "totalwaitms %u\n", probe->totalwaitms);
        if (probe->tcpwrappedms)
            fprintf(fp, "tcpwrappedms %u\n", probe->tcpwrappedms);
        _nmapservice_print_ports(&probe->ports, fp, "ports", probe->protocol);
        _nmapservice_print_ports(&probe->sslports, fp, "sslports",
                                 probe->protocol);

        for (match = probe->match; match; match = match->next) {
            struct ServiceVersionInfo *vi;

            fprintf(fp, "match %s m", match->service);
            nmapserviceprobes_print_dstring(fp, match->regex,
                                            match->regex_length, '/');
            if (match->is_case_insensitive)
                fprintf(fp, "i");
            if (match->is_include_newlines)
                fprintf(fp, "s");
            fprintf(fp, " ");

            for (vi = match->versioninfo; vi; vi = vi->next) {
                const char *tag;
                switch (vi->type) {
                    case SvcV_Unknown:
                        tag = "u";
                        break;
                    case SvcV_ProductName:
                        tag = "p";
                        break;
                    case SvcV_Version:
                        tag = "v";
                        break;
                    case SvcV_Info:
                        tag = "i";
                        break;
                    case SvcV_Hostname:
                        tag = "h";
                        break;
                    case SvcV_OperatingSystem:
                        tag = "o";
                        break;
                    case SvcV_DeviceType:
                        tag = "e";
                        break;
                    case SvcV_CpeName:
                        tag = "cpe:";
                        break;
                    default:
                        tag = "";
                }
                fprintf(fp, "%s", tag);
                nmapserviceprobes_print_dstring(fp, vi->value,
                                                strlen(vi->value), '/');
                if (vi->is_a)
                    fprintf(fp, "a");
                fprintf(fp, " ");
            }
            fprintf(fp, "\n");
        }
    }
}

/*****************************************************************************
 *****************************************************************************/
void nmapservice_match_compile(struct NmapServiceProbeList *service_probes) {
    struct ServiceProbeMatch *match;
    int                       pcre2_errcode;
    PCRE2_SIZE                pcre2_erroffset;

    for (unsigned i = 0; i < service_probes->count; i++) {
        match = service_probes->probes[i]->match;
        for (; match; match = match->next) {
            if (match->compiled_re)
                continue;

            match->compiled_re = pcre2_compile(
                (PCRE2_SPTR)match->regex, PCRE2_ZERO_TERMINATED,
                (match->is_case_insensitive ? PCRE2_CASELESS : 0) |
                    (match->is_include_newlines ? PCRE2_DOTALL : 0),
                &pcre2_errcode, &pcre2_erroffset, NULL);

            if (!match->compiled_re) {
                LOG(LEVEL_HINT, "regex compiled failed.\n");
                continue;
            }

            match->match_ctx = pcre2_match_context_create(NULL);

            if (!match->match_ctx) {
                LOG(LEVEL_HINT, "regex allocates match_ctx failed.\n");
                continue;
            }

            pcre2_set_match_limit(match->match_ctx, 100000);

#ifdef pcre2_set_depth_limit
            // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for
            // function names, so we don't have to add this to configure.ac.
            pcre2_set_depth_limit(match->match_ctx, 10000);
#else
            pcre2_set_recursion_limit(match->match_ctx, 10000);
#endif
        }
    }
}

/*****************************************************************************
 *****************************************************************************/
struct NmapServiceProbe *
nmapservice_get_probe_by_name(struct NmapServiceProbeList *list,
                              const char *name, unsigned protocol) {
    struct NmapServiceProbe *probe_res = NULL;

    for (unsigned i = 0; i < list->count; i++) {
        if (list->probes[i]->protocol == protocol) {
            if (0 == strcmp(name, list->probes[i]->name)) {
                probe_res = list->probes[i];
                break;
            }
        }
    }

    return probe_res;
}

/*****************************************************************************
 *****************************************************************************/
void nmapservice_link_fallback(struct NmapServiceProbeList *list) {
    for (unsigned i = 1; i < list->count; i++) {
        struct ServiceProbeFallback *fallback = NULL;
        for (fallback = list->probes[i]->fallback; fallback;
             fallback = fallback->next) {
            fallback->probe = nmapservice_get_probe_by_name(
                list, fallback->name, list->probes[i]->protocol);
        }
    }
}

/*****************************************************************************
 *****************************************************************************/
void nmapservice_match_free(struct NmapServiceProbeList *list) {
    struct ServiceProbeMatch *match;

    for (unsigned i = 0; i < list->count; i++) {
        match = list->probes[i]->match;
        for (; match; match = match->next) {
            if (match->compiled_re) {
                pcre2_code_free(match->compiled_re);
                match->compiled_re = NULL;

                if (match->match_ctx) {
                    pcre2_match_context_free(match->match_ctx);
                    match->match_ctx = NULL;
                }
            }
        }
    }
}

/*****************************************************************************
 *****************************************************************************/
void nmapservice_free(struct NmapServiceProbeList *list) {
    unsigned i;

    if (list == NULL)
        return;

    for (i = 0; i < list->count; i++) {
        nmapserviceprobes_free_record(list->probes[i]);
    }

    FREE(list->probes);
    FREE(list);
}

/**
 * does probe has at least one hard match for this service?
 */
static bool has_hardmatch(const struct NmapServiceProbe *probe,
                          const char                    *service) {
    if (!probe->match)
        return 0;

    struct ServiceProbeMatch *match;
    for (match = probe->match; match; match = match->next) {
        if (!match->is_softmatch && strcmp(match->service, service) == 0) {
            return true;
        }
    }

    return false;
}

unsigned nmapservice_next_probe_index(const struct NmapServiceProbeList *list,
                                      unsigned idx_now, unsigned port_them,
                                      unsigned rarity, unsigned protocol,
                                      const char *softmatch) {
    unsigned next_probe = 0;

    if (idx_now < list->count - 1) {
        for (unsigned i = idx_now + 1; i < list->count; i++) {
            /*validate protocol & rarity*/
            if (list->probes[i]->protocol == protocol &&
                list->probes[i]->rarity <= rarity) {
                /*port is in the range or ignored*/
                if (port_them > 0 &&
                    0 >= rangelist_is_contains(&list->probes[i]->ports,
                                               port_them)) {
                    continue;
                }

                /*if softmatch specified, we need specified hard match*/
                if (softmatch && !has_hardmatch(list->probes[i], softmatch)) {
                    continue;
                }

                next_probe = i;
                break;
            }
        }
    }

    return next_probe;
}

/**
 * do matching in one probe
 * @param probe probe used to match
 * @param payload data of payload
 * @param payload_len len of data
 * @param softmatch just do hardmatching for this softmatch service
 * @return matched struct from service_probes or NULL if not matched.
 */
static struct ServiceProbeMatch *
match_service_in_one_probe(const struct NmapServiceProbe *probe,
                           const unsigned char *payload, size_t payload_len,
                           const char *softmatch) {
    struct ServiceProbeMatch *match_res  = NULL;
    pcre2_match_data         *match_data = NULL;
    struct ServiceProbeMatch *m;
    int                       rc;

    for (m = probe->match; m; m = m->next) {
        if (softmatch && m->is_softmatch)
            continue;

        if (softmatch && strcmp(softmatch, m->service) != 0)
            continue;

        if (m->compiled_re) {
            match_data =
                pcre2_match_data_create_from_pattern(m->compiled_re, NULL);
            if (!match_data) {
                LOG(LEVEL_ERROR,
                    "cannot allocate match_data when matching in probe %s.\n",
                    probe->name);
                match_res = NULL;
                break;
            }

            rc = pcre2_match(m->compiled_re, (PCRE2_SPTR8)payload,
                             (int)payload_len, 0, 0, match_data, m->match_ctx);

            /*matched one. ps: "offset is too small" means successful, too*/
            if (rc >= 0) {
                match_res = m;
                pcre2_match_data_free(match_data);
                match_data = NULL;
                break;
            }

            pcre2_match_data_free(match_data);
        }
    }

    return match_res;
}

struct ServiceProbeMatch *
nmapservice_match_service(const struct NmapServiceProbeList *list,
                          const struct NmapServiceProbe     *probe,
                          const unsigned char *payload, size_t payload_len,
                          unsigned protocol, const char *softmatch) {
    struct ServiceProbeMatch *match_res = NULL;

    match_res =
        match_service_in_one_probe(probe, payload, payload_len, softmatch);

    if (match_res)
        return match_res;

    /*has fallback? try match all*/
    struct ServiceProbeFallback *fallback = probe->fallback;

    for (; fallback; fallback = fallback->next) {
        /*fallback must have been linked*/
        if (fallback->probe) {
            match_res = match_service_in_one_probe(fallback->probe, payload,
                                                   payload_len, softmatch);
            /*matched*/
            if (match_res)
                break;
        }
    }

    if (match_res)
        return match_res;

    /*match with NULL probe at last if it's TCP and probe is not NULL*/
    if (protocol == IP_PROTO_TCP && probe->hellolength != 0) {
        match_res = match_service_in_one_probe(list->probes[0], payload,
                                               payload_len, softmatch);
    }

    return match_res;
}

/*****************************************************************************
 *****************************************************************************/
int nmapservice_selftest() {
    const char *lines[] = {
        "Exclude 53,T:9100,U:30000-40000\n",
        "Probe UDP DNSStatusRequest "
        "q|\\0\\0\\x10\\0\\0\\0\\0\\0\\0\\0\\0\\0|\n",
        "Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|\n",
        "ports 80\n",
        "sslports 443\n",
        "Probe TCP NULL q||\n",
        "ports 21,43,110,113,199,505,540,1248,5432,30444\n",
        "match ftp m/^220.*Welcome to .*Pure-?FTPd (\\d\\S+\\s*)/ p/Pure-FTPd/ "
        "v/$1/ cpe:/a:pureftpd:pure-ftpd:$1/\n",
        "match ssh m/^SSH-([\\d.]+)-OpenSSH[_-]([\\w.]+)\\r?\\n/i p/OpenSSH/ "
        "v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/\n",
        "match mysql m|^\\x10\\0\\0\\x01\\xff\\x13\\x04Bad handshake$| "
        "p/MySQL/ cpe:/a:mysql:mysql/\n",
        "match chargen m|@ABCDEFGHIJKLMNOPQRSTUVWXYZ|\n",
        "match uucp m|^login: login: login: $| p/NetBSD uucpd/ o/NetBSD/ "
        "cpe:/o:netbsd:netbsd/a\n",
        "match printer m|^([\\w-_.]+): lpd: Illegal service request\\n$| "
        "p/lpd/ h/$1/\n",
        "match afs m|^[\\d\\D]{28}\\s*(OpenAFS)([\\d\\.]{3}[^\\s\\0]*)\\0| "
        "p/$1/ v/$2/\n",
        0};
    unsigned                     i;
    struct NmapServiceProbeList *list = _nmapservice_new_list("<selftest>");

    for (i = 0; lines[i]; i++) {
        list->line_number = i;
        _parse_line(list, lines[i]);
    }

    // nmapserviceprobes_print(list, stdout);
    return 0;
}

#endif /*ifndef NOT_FOUND_PCRE2*/