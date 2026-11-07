#ifndef PROTO_MATCH_H
#define PROTO_MATCH_H

#include <stdbool.h>
#include <stddef.h>

#ifndef NOT_FOUND_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

typedef enum MatchScope {
    MATCH_SCOPE_ALL = 0,
    MATCH_SCOPE_HEADERS = 1,
    MATCH_SCOPE_BODY = 2,
} MatchScope;

typedef struct MatchSpec {
    char    *keyword;
    char    *regex;
    unsigned scope;
    unsigned configured : 1;
    unsigned case_insensitive : 1;
    unsigned include_newlines : 1;
#ifndef NOT_FOUND_PCRE2
    pcre2_code          *compiled_re;
    pcre2_match_context *match_ctx;
#endif
} MatchSpec;

typedef struct MatchResult {
    bool     matched;
    unsigned scope;
    const char *kind;
    char     text[256];
} MatchResult;

bool match_spec_set_keyword(MatchSpec *spec, const char *value);
bool match_spec_set_regex(MatchSpec *spec, const char *value);
bool match_spec_set_scope(MatchSpec *spec, const char *value);
void match_spec_set_case_insensitive(MatchSpec *spec, bool value);
void match_spec_set_include_newlines(MatchSpec *spec, bool value);
bool match_spec_finalize(MatchSpec *spec);
void match_spec_free(MatchSpec *spec);

/*
 * |all| is the complete canonical response, |headers| the header section and
 * |body| the entity body. Any pointer may be NULL/zero for a missing scope.
 */
bool match_spec_apply(const MatchSpec *spec, const void *all, size_t all_len,
                      const void *headers, size_t headers_len,
                      const void *body, size_t body_len, MatchResult *result);

const char *match_scope_name(unsigned scope);

#endif
