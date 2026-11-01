#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "xprint.h"

/*
 * Display width for the help output.
 *
 * We deliberately avoid a full Unicode database: help text only needs to wrap
 * Latin, CJK and the common full-width punctuation correctly. UTF-8 is decoded
 * so a wide character counts as two terminal columns; invalid bytes fall back
 * to one column and are printed as-is.
 */
static int _utf8_decode(const unsigned char *s, size_t len, size_t *advance,
                        uint32_t *cp) {
    unsigned char c = s[0];

    if (c < 0x80) {
        *advance = 1;
        *cp      = c;
        return 1;
    }
    if ((c & 0xE0) == 0xC0 && len >= 2) {
        *advance = 2;
        *cp      = ((uint32_t)(c & 0x1F) << 6) | (s[1] & 0x3F);
        return 1;
    }
    if ((c & 0xF0) == 0xE0 && len >= 3) {
        *advance = 3;
        *cp = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) |
              (s[2] & 0x3F);
        return 1;
    }
    if ((c & 0xF8) == 0xF0 && len >= 4) {
        *advance = 4;
        *cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12) |
              ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 1;
    }

    *advance = 1;
    *cp      = c;
    return 0;
}

static int _no_break_before(uint32_t cp) {
    /* ASCII and common CJK closing punctuation must not start a new line. */
    if (cp == ',' || cp == '.' || cp == ';' || cp == ':' || cp == '!' ||
        cp == '?' || cp == ')' || cp == ']' || cp == '}' || cp == '%')
        return 1;

    switch (cp) {
        case 0x3001: /* 、 */
        case 0x3002: /* 。 */
        case 0x3009: /* 〉 */
        case 0x300B: /* 》 */
        case 0x300D: /* 」 */
        case 0x300F: /* 』 */
        case 0x3011: /* 】 */
        case 0x3015: /* 〕 */
        case 0x3017: /* 〗 */
        case 0x3019: /* 〙 */
        case 0x301B: /* 〛 */
        case 0xFF01: /* ！ */
        case 0xFF09: /* ） */
        case 0xFF0C: /* ， */
        case 0xFF0E: /* ． */
        case 0xFF1A: /* ： */
        case 0xFF1B: /* ； */
        case 0xFF1F: /* ？ */
        case 0xFF3D: /* ］ */
        case 0xFF5D: /* ｝ */
            return 1;
        default:
            return 0;
    }
}

static unsigned _display_width(uint32_t cp) {
    /* Combining marks: no column. */
    if ((cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) ||
        (cp >= 0x1DC0 && cp <= 0x1DFF) || (cp >= 0x20D0 && cp <= 0x20FF) ||
        (cp >= 0xFE20 && cp <= 0xFE2F))
        return 0;

    /* CJK, Hangul, full-width forms and common emoji. */
    if ((cp >= 0x1100 && cp <= 0x115F) ||
        (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
        (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
        (cp >= 0xFE10 && cp <= 0xFE19) || (cp >= 0xFE30 && cp <= 0xFE6F) ||
        (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6) ||
        (cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x20000 && cp <= 0x3FFFD))
        return 2;

    return 1;
}

static void _xprint_impl(const char *text, unsigned indent, unsigned count,
                         int trim_leading_spaces) {
    size_t len = strlen(text);
    if (len == 0)
        return;
    if (count == 0)
        return;
    if (count <= indent)
        return;

    unsigned c = 0;
    size_t   i = 0;
    while (i < len) {
        size_t   advance = 1;
        uint32_t cp      = 0;
        _utf8_decode((const unsigned char *)text + i, len - i, &advance, &cp);

        if (cp == '\n') {
            printf("\n%*s", indent, "");
            c = indent;
            i += advance;
            continue;
        }

        if (c == 0) {
            printf("%*s", indent, "");
            c = indent;
        }

        if (trim_leading_spaces && c == indent && cp == ' ') {
            i += advance;
            continue;
        }

        unsigned width = _display_width(cp);
        if (width > 0 && c > indent && c + width > count &&
            !_no_break_before(cp)) {
            printf("\n");
            c = 0;
            /* Let the same character start the next indented line. */
            continue;
        }

        fwrite(text + i, 1, advance, stdout);
        c += width;
        i += advance;

        if (c >= count) {
            printf("\n");
            c = 0;
        }
    }
}

void xprint(const char *text, unsigned indent, unsigned count) {
    _xprint_impl(text, indent, count, 1);
}

void xprint_with_head(const char *text, unsigned indent, unsigned count) {
    _xprint_impl(text, indent, count, 0);
}
