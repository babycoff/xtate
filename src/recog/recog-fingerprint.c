#ifndef NOT_FOUND_PCRE2

#include "recog-fingerprint.h"

#ifndef NOT_FOUND_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"

struct RecogMatch {
    char                *desc;
    pcre2_code          *compiled_re;
    pcre2_match_context *match_ctx;
    struct RecogMatch   *next;
};

struct Recog_FP {
    char              *filename;
    struct RecogMatch *match;
    unsigned           count;
};

struct Recog_FP *load_recog_fp(const char *filename, bool unprefix,
                               bool unsuffix) {
#ifndef NOT_FOUND_LIBXML2

    if (filename == NULL || filename[0] == '\0') {
        LOG(LEVEL_ERROR, "invalid file name\n");
        return NULL;
    }

    xmlDocPtr  doc;
    xmlNodePtr cur_node;
    xmlNodePtr cur_subnode;
    xmlChar   *tmp_xml_char;

    doc = xmlParseFile(filename);
    if (doc == NULL) {
        LOG(LEVEL_ERROR, "failed to load xml file %s.\n", filename);
        return NULL;
    }

    cur_node = xmlDocGetRootElement(doc);
    if (cur_node == NULL) {
        LOG(LEVEL_ERROR, "empty xml file %s.\n", filename);
        xmlFreeDoc(doc);
        return NULL;
    }

    struct Recog_FP   *fp;
    struct RecogMatch *match;

    fp           = CALLOC(1, sizeof(struct Recog_FP));
    fp->match    = CALLOC(1, sizeof(struct RecogMatch));
    fp->filename = STRDUP(filename);
    match        = fp->match;

    int        pcre2_errcode;
    size_t     regex_len;
    bool       icase;
    bool       mline;
    PCRE2_SIZE pcre2_erroffset;

    for (cur_node = cur_node->children; cur_node; cur_node = cur_node->next) {
        if (xmlStrcmp(cur_node->name, (const xmlChar *)"fingerprint"))
            continue;

        /*regex flags*/
        icase        = false;
        mline        = false;
        tmp_xml_char = xmlGetProp(cur_node, (const xmlChar *)"flags");
        if (tmp_xml_char) {
            /* Match by content, not by string length: unrelated flags of the
             * same length used to enable case-insensitive/multiline mode. */
            if (strstr((char *)tmp_xml_char, "REG_ICASE"))
                icase = true;
            if (strstr((char *)tmp_xml_char, "REG_MULTILINE"))
                mline = true;
            xmlFree(tmp_xml_char);
        }

        tmp_xml_char = xmlGetProp(cur_node, (const xmlChar *)"pattern");
        if (!tmp_xml_char) {
            continue;
        }

        regex_len      = strlen((char *)tmp_xml_char);
        char *tmp_char = MALLOC(regex_len + 1);
        if (unprefix && tmp_xml_char[0] == '^') {
            safe_strcpy(tmp_char, regex_len + 1, (char *)tmp_xml_char + 1);
            regex_len--;
        } else {
            safe_strcpy(tmp_char, regex_len + 1, (char *)tmp_xml_char);
        }

        if (regex_len == 0) {
            /* Empty pattern (e.g. "^" with --unprefix removed): nothing to
             * compile, and tmp_char[regex_len-1] below would underflow. */
            LOG(LEVEL_HINT, "empty regex pattern in %s.\n", tmp_xml_char);
            FREE(tmp_char);
            xmlFree(tmp_xml_char);
            continue;
        }

        if (unsuffix && tmp_char[regex_len - 1] == '$') {
            tmp_char[regex_len - 1] = '\0';
        }

        match->compiled_re = pcre2_compile(
            (PCRE2_SPTR)tmp_char, PCRE2_ZERO_TERMINATED,
            (icase ? PCRE2_CASELESS : 0) | (mline ? PCRE2_MULTILINE : 0),
            &pcre2_errcode, &pcre2_erroffset, NULL);

        FREE(tmp_char);

        if (!match->compiled_re) {
            LOG(LEVEL_HINT, "regex compiled failed in %s.\n", tmp_xml_char);
            xmlFree(tmp_xml_char);
            continue;
        }

        match->match_ctx = pcre2_match_context_create(NULL);
        if (!match->match_ctx) {
            LOG(LEVEL_HINT, "regex allocates match_ctx failed in %s.\n",
                tmp_xml_char);
            xmlFree(tmp_xml_char);
            pcre2_code_free(match->compiled_re);
            continue;
        }

        xmlFree(tmp_xml_char);

        pcre2_set_match_limit(match->match_ctx, 100000);

#ifdef pcre2_set_depth_limit
        // Changed name in PCRE2 10.30. PCRE2 uses macro definitions for
        // function names, so we don't have to add this to configure.ac.
        pcre2_set_depth_limit(match->match_ctx, 10000);
#else
        pcre2_set_recursion_limit(match->match_ctx, 10000);
#endif

        /*get describe*/
        tmp_xml_char = NULL;
        cur_subnode  = cur_node->children;
        while (cur_subnode) {
            if (!xmlStrcmp(cur_subnode->name, (const xmlChar *)"description")) {
                if (cur_subnode->children) {
                    tmp_xml_char = cur_subnode->children->content;
                }
                break;
            }
            cur_subnode = cur_subnode->next;
        }

        if (tmp_xml_char) {
            match->desc = STRDUP((char *)tmp_xml_char);
        } else {
            /*use line number if no description*/
            match->desc = MALLOC(20);
            snprintf(match->desc, 20, "line<%u>", cur_node->line);
        }

        fp->count++;
        match->next = CALLOC(1, sizeof(struct RecogMatch));
        match       = match->next;
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    if (!fp->count)
        goto error;

    LOG(LEVEL_HINT, "loaded %u recog fingerprints in file %s.\n", fp->count,
        fp->filename);

    return fp;

error:
    LOG(LEVEL_ERROR, "failed to load fingerprints in file %s.\n", filename);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    FREE(fp->filename);
    FREE(fp);
    /*some loaded matches may be leaked, but it's acceptable while loading
     * error*/

    return NULL;

#else

    LOG(LEVEL_ERROR,
        "failed to load recog fingerprints because no libxml2 build with.\n");
    return NULL;

#endif
}

const char *match_recog_fp(struct Recog_FP *fp, const unsigned char *payload,
                           size_t payload_len) {
    if (!fp)
        return NULL;

    char              *match_res  = NULL;
    struct RecogMatch *match      = fp->match;
    pcre2_match_data  *match_data = NULL;
    int                rc;

    for (; match; match = match->next) {
        if (match->compiled_re) {
            match_data =
                pcre2_match_data_create_from_pattern(match->compiled_re, NULL);
            if (!match_data) {
                LOG(LEVEL_ERROR,
                    "cannot allocate match_data when matching in probe %s.\n",
                    match->desc);
                return NULL;
            }

            rc = pcre2_match(match->compiled_re, (PCRE2_SPTR8)payload,
                             (int)payload_len, 0, 0, match_data,
                             match->match_ctx);

            /*matched one. ps: "offset is too small" means successful, too*/
            if (rc >= 0) {
                match_res = match->desc;
                pcre2_match_data_free(match_data);
                match_data = NULL;
                break;
            }

            pcre2_match_data_free(match_data);
        }
    }

    return match_res;
}

void free_recog_fp(struct Recog_FP *fp) {
    if (!fp)
        return;

    struct RecogMatch *match = fp->match;
    struct RecogMatch *tmp;
    for (; match;) {
        FREE(match->desc);
        if (match->compiled_re)
            pcre2_code_free(match->compiled_re);
        if (match->match_ctx)
            pcre2_match_context_free(match->match_ctx);

        tmp   = match;
        match = match->next;
        FREE(tmp);
    }
}

#endif /*ifndef NOT_FOUND_PCRE2*/