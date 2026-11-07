#include "proto-match.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "../util-data/fine-malloc.h"
#include "../util-misc/configer.h"
#include "../util-misc/misc.h"
#include "../util-out/logger.h"

static bool match_contains(const unsigned char *hay, size_t hay_len,
                           const unsigned char *needle, size_t needle_len,
                           bool insensitive) {
    if (needle_len == 0)
        return true;
    if (hay_len < needle_len)
        return false;
    if (!insensitive) {
        for (size_t i = 0; i + needle_len <= hay_len; i++)
            if (memcmp(hay + i, needle, needle_len) == 0)
                return true;
        return false;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        size_t j = 0;
        while (j < needle_len &&
               tolower((unsigned char)hay[i + j]) ==
                   tolower((unsigned char)needle[j]))
            j++;
        if (j == needle_len)
            return true;
    }
    return false;
}

bool match_spec_set_keyword(MatchSpec *spec, const char *value) {
    if (!spec || !value || !*value)
        return false;
    FREE(spec->keyword);
    spec->keyword = STRDUP(value);
    return spec->keyword != NULL;
}

bool match_spec_set_regex(MatchSpec *spec, const char *value) {
    if (!spec || !value || !*value)
        return false;
    FREE(spec->regex);
    spec->regex = STRDUP(value);
    return spec->regex != NULL;
}

bool match_spec_set_scope(MatchSpec *spec, const char *value) {
    if (!spec || !value)
        return false;
    if (conf_equals(value, "all"))
        spec->scope = MATCH_SCOPE_ALL;
    else if (conf_equals(value, "headers"))
        spec->scope = MATCH_SCOPE_HEADERS;
    else if (conf_equals(value, "body"))
        spec->scope = MATCH_SCOPE_BODY;
    else
        return false;
    return true;
}

void match_spec_set_case_insensitive(MatchSpec *spec, bool value) {
    if (spec)
        spec->case_insensitive = value;
}

void match_spec_set_include_newlines(MatchSpec *spec, bool value) {
    if (spec)
        spec->include_newlines = value;
}

bool match_spec_finalize(MatchSpec *spec) {
    if (!spec)
        return false;
    if (spec->keyword && spec->regex) {
        LOG(LEVEL_ERROR, "match: --keyword and --regex are mutually exclusive\n");
        return false;
    }
    spec->configured = (spec->keyword || spec->regex);
    if (!spec->configured)
        return true;

#ifndef NOT_FOUND_PCRE2
    if (spec->regex) {
        int        errcode;
        PCRE2_SIZE erroffset;
        if (spec->compiled_re)
            pcre2_code_free(spec->compiled_re);
        if (spec->match_ctx)
            pcre2_match_context_free(spec->match_ctx);
        spec->compiled_re = pcre2_compile(
            (PCRE2_SPTR)spec->regex, PCRE2_ZERO_TERMINATED,
            (spec->case_insensitive ? PCRE2_CASELESS : 0) |
                (spec->include_newlines ? PCRE2_DOTALL : 0),
            &errcode, &erroffset, NULL);
        if (!spec->compiled_re) {
            LOG(LEVEL_ERROR, "match: regex compile failed at offset %zu\n",
                (size_t)erroffset);
            return false;
        }
        spec->match_ctx = pcre2_match_context_create(NULL);
        if (!spec->match_ctx)
            return false;
        pcre2_set_match_limit(spec->match_ctx, 100000);
#ifdef pcre2_set_depth_limit
        pcre2_set_depth_limit(spec->match_ctx, 10000);
#endif
    }
#else
    if (spec->regex) {
        LOG(LEVEL_ERROR, "match: regex support is not compiled in\n");
        return false;
    }
#endif
    return true;
}

void match_spec_free(MatchSpec *spec) {
    if (!spec)
        return;
    FREE(spec->keyword);
    FREE(spec->regex);
#ifndef NOT_FOUND_PCRE2
    if (spec->compiled_re)
        pcre2_code_free(spec->compiled_re);
    if (spec->match_ctx)
        pcre2_match_context_free(spec->match_ctx);
    spec->compiled_re = NULL;
    spec->match_ctx = NULL;
#endif
    memset(spec, 0, sizeof(*spec));
}

const char *match_scope_name(unsigned scope) {
    switch (scope) {
        case MATCH_SCOPE_HEADERS: return "headers";
        case MATCH_SCOPE_BODY: return "body";
        default: return "all";
    }
}

bool match_spec_apply(const MatchSpec *spec, const void *all, size_t all_len,
                      const void *headers, size_t headers_len,
                      const void *body, size_t body_len, MatchResult *result) {
    MatchResult dummy;
    if (!result)
        result = &dummy;
    memset(result, 0, sizeof(*result));
    result->scope = spec ? spec->scope : MATCH_SCOPE_ALL;
    if (!spec || !spec->configured) {
        result->matched = true;
        result->kind = "none";
        return true;
    }

    const unsigned char *hay = NULL;
    size_t hay_len = 0;
    if (spec->scope == MATCH_SCOPE_HEADERS) {
        hay = headers;
        hay_len = headers_len;
    } else if (spec->scope == MATCH_SCOPE_BODY) {
        hay = body;
        hay_len = body_len;
    } else {
        hay = all;
        hay_len = all_len;
    }
    if (!hay) {
        hay = (const unsigned char *)"";
        hay_len = 0;
    }

    if (spec->keyword) {
        size_t klen = strlen(spec->keyword);
        result->kind = "keyword";
        result->matched = match_contains(hay, hay_len,
                                         (const unsigned char *)spec->keyword,
                                         klen, spec->case_insensitive);
        if (result->matched) {
            size_t n = klen < sizeof(result->text) - 1 ? klen
                                                       : sizeof(result->text) - 1;
            memcpy(result->text, spec->keyword, n);
            result->text[n] = '\0';
        }
        return result->matched;
    }

#ifndef NOT_FOUND_PCRE2
    if (spec->compiled_re) {
        pcre2_match_data *md =
            pcre2_match_data_create_from_pattern(spec->compiled_re, NULL);
        if (!md) {
            result->kind = "regex";
            return false;
        }
        int rc = pcre2_match(spec->compiled_re, (PCRE2_SPTR8)hay, (int)hay_len,
                             0, 0, md, spec->match_ctx);
        result->kind = "regex";
        result->matched = rc >= 0;
        if (rc >= 0) {
            PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
            if (ov && ov[1] > ov[0]) {
                size_t n = (size_t)(ov[1] - ov[0]);
                if (n >= sizeof(result->text))
                    n = sizeof(result->text) - 1;
                memcpy(result->text, hay + ov[0], n);
                result->text[n] = '\0';
            }
        }
        pcre2_match_data_free(md);
        return result->matched;
    }
#endif
    result->kind = "keyword";
    result->matched = false;
    return false;
}
