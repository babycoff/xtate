#include "as-query.h"
#include "../util-data/file-open.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "../target/target-parse.h"
#include "../util-misc/configer.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"

#define COUNT_BUF_SIZE 65536

struct AS_Item {
    ipv4address    begin;
    ipv4address    end;
    struct AS_Info as_info;
};

struct AS_Table {
    uint64_t       list_len;
    uint64_t       list_size;
    struct AS_Item list[0]; /*ordered list*/
};

struct AS6_Item {
    ipv6address    begin;
    ipv6address    end;
    struct AS_Info as_info;
};

struct AS6_Table {
    uint64_t        list_len;
    uint64_t        list_size;
    struct AS6_Item list[0]; /*ordered list*/
};

struct AS_Query {
    struct AS_Table  *as_table;
    struct AS6_Table *as6_table;
};

/**
 * count lines('\n') of a given file and reset the FILE pointer.
 */
static uint64_t _count_lines(FILE *file) {
    char buf[COUNT_BUF_SIZE];
    rewind(file);
    uint64_t counter = 0;
    for (;;) {
        size_t res = fread(buf, 1, COUNT_BUF_SIZE, file);
        if (ferror(file)) {
            LOGPERROR("fread");
            return 0;
        }

        int i;
        for (i = 0; i < res; i++)
            if (buf[i] == '\n')
                counter++;

        if (feof(file)) {
            break;
        }
    }
    rewind(file);
    return counter;
}

struct AS_Query *as_query_new(const char *filename_v4,
                              const char *filename_v6) {
    char              line[1024];
    FILE             *fp_v4;
    FILE             *fp_v6;
    uint64_t          line_count_v4;
    uint64_t          line_count_v6;
    uint64_t          as_item_count_v4 = 0;
    uint64_t          as_item_count_v6 = 0;
    struct AS_Query  *as_query         = NULL;
    struct AS_Table  *as_table_v4      = NULL;
    struct AS6_Table *as_table_v6      = NULL;

    if (filename_v4 != NULL) {
        fp_v4 = file_open_utf8_mode(filename_v4, "rb");
        if (fp_v4 == NULL) {
            LOGPERROR("fopen");
            goto no_as_v4;
        }

        line_count_v4 = _count_lines(fp_v4);
        if (line_count_v4 <= 0) {
            LOG(LEVEL_WARN, "(%s) not a complete AS info in file %s.\n",
                __func__, filename_v4);
            goto invalid_as_v4;
        }

        as_table_v4 = MALLOC(line_count_v4 * sizeof(struct AS_Item) +
                             sizeof(struct AS_Table));

        as_table_v4->list_len  = 0;
        as_table_v4->list_size = line_count_v4;

        while (as_item_count_v4 < as_table_v4->list_size) {
            char *ip_begin = fgets(line, sizeof(line), fp_v4);

            if (ip_begin == NULL) {
                if (ferror(fp_v4))
                    LOG(LEVEL_DEBUG, "(%s) error of file %s.\n", __func__,
                        filename_v4);
                else if (feof(fp_v4))
                    LOG(LEVEL_DEBUG, "(%s) EOF of file %s.\n", __func__,
                        filename_v4);
                break;
            }

            /*absolute null line or the last line*/
            if (ip_begin[0] == '\n' || ip_begin[0] == '\r') {
                continue;
            }

            /*split*/
            char *ip_end = strchr(ip_begin, '\t');
            if (ip_end == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            ip_end++;
            char *asn_str = strchr(ip_end, '\t');
            if (asn_str == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            asn_str++;
            char *cc_str = strchr(asn_str, '\t');
            if (cc_str == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            cc_str++;
            char *desc_str = strchr(cc_str, '\t');
            if (desc_str == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            desc_str++;
            char *last = strchr(desc_str, '\n');
            if (last == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }

            ip_end[-1]   = '\0';
            asn_str[-1]  = '\0';
            cc_str[-1]   = '\0';
            desc_str[-1] = '\0';
            last[0]      = '\0';

            /*
             * kludge: too tired so that assume the line format is correct.
             *
             * Love and hate C. Sometimes want C++ or Rust, even Golang...
             */
            as_table_v4->list[as_item_count_v4].begin =
                target_parse_ipv4(ip_begin);
            as_table_v4->list[as_item_count_v4].end = target_parse_ipv4(ip_end);
            if (as_table_v4->list[as_item_count_v4].begin == (unsigned)~0 ||
                as_table_v4->list[as_item_count_v4].end == (unsigned)~0) {
                continue;
            }

            as_table_v4->list[as_item_count_v4].as_info.asn =
                conf_parse_int(asn_str);
            as_table_v4->list[as_item_count_v4].as_info.country_code =
                STRDUP(cc_str);
            as_table_v4->list[as_item_count_v4].as_info.desc = STRDUP(desc_str);

            as_item_count_v4++;
        }
        as_table_v4->list_len = as_item_count_v4;
        LOG(LEVEL_HINT, "loaded %" PRIu64 " IPv4 AS items.\n",
            as_item_count_v4);

    invalid_as_v4:
        fclose(fp_v4);
    }

no_as_v4:

    if (filename_v6 != NULL) {
        fp_v6 = file_open_utf8_mode(filename_v6, "rb");
        if (fp_v6 == NULL) {
            LOGPERROR("fopen");
            goto no_as_v6;
        }

        line_count_v6 = _count_lines(fp_v6);
        if (line_count_v6 <= 0) {
            LOG(LEVEL_WARN, "(%s) not a complete AS info in file %s.\n",
                __func__, filename_v6);
            goto invalid_as_v6;
        }

        as_table_v6           = MALLOC(line_count_v6 * sizeof(struct AS6_Item) +
                                       sizeof(struct AS6_Table));
        as_table_v6->list_len = 0;
        as_table_v6->list_size = line_count_v6;

        while (as_item_count_v6 < as_table_v6->list_size) {
            char *ip_begin = fgets(line, sizeof(line), fp_v6);

            if (ip_begin == NULL) {
                if (ferror(fp_v6))
                    LOG(LEVEL_DEBUG, "(%s) error of file %s.\n", __func__,
                        filename_v6);
                else if (feof(fp_v6))
                    LOG(LEVEL_DEBUG, "(%s) EOF of file %s.\n", __func__,
                        filename_v6);
                break;
            }

            /*absolute null line or the last line*/
            if (ip_begin[0] == '\n' || ip_begin[0] == '\r') {
                continue;
            }

            /*split*/
            char *ip_end = strchr(ip_begin, '\t');
            if (ip_end == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            ip_end++;
            char *asn_str = strchr(ip_end, '\t');
            if (asn_str == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            asn_str++;
            char *cc_str = strchr(asn_str, '\t');
            if (cc_str == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            cc_str++;
            char *desc_str = strchr(cc_str, '\t');
            if (desc_str == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }
            desc_str++;
            char *last = strchr(desc_str, '\n');
            if (last == NULL) {
                LOG(LEVEL_WARN, "(%s) invalid line '%s'.\n", __func__, line);
                continue;
            }

            ip_end[-1]   = '\0';
            asn_str[-1]  = '\0';
            cc_str[-1]   = '\0';
            desc_str[-1] = '\0';
            last[0]      = '\0';

            /*
             * kludge: too tired so that assume the line format is correct.
             *
             * Love and hate C. Sometimes want C++ or Rust, even Golang...
             */
            as_table_v6->list[as_item_count_v6].begin =
                target_parse_ipv6(ip_begin);
            as_table_v6->list[as_item_count_v6].end = target_parse_ipv6(ip_end);

            if ((as_table_v6->list[as_item_count_v6].begin.hi == ~0ULL &&
                 as_table_v6->list[as_item_count_v6].begin.lo == ~0ULL) ||
                (as_table_v6->list[as_item_count_v6].end.hi == ~0ULL &&
                 as_table_v6->list[as_item_count_v6].end.lo == ~0ULL)) {
                continue;
            }

            as_table_v6->list[as_item_count_v6].as_info.asn =
                conf_parse_int(asn_str);
            as_table_v6->list[as_item_count_v6].as_info.country_code =
                STRDUP(cc_str);
            as_table_v6->list[as_item_count_v6].as_info.desc = STRDUP(desc_str);

            as_item_count_v6++;
        }
        as_table_v6->list_len = as_item_count_v6;
        LOG(LEVEL_HINT, "loaded %" PRIu64 " IPv6 AS items.\n",
            as_item_count_v6);

    invalid_as_v6:
        fclose(fp_v6);
    }

no_as_v6:

    if (as_table_v4 == NULL && as_table_v6 == NULL) {
        ;
    } else {
        as_query            = MALLOC(sizeof(struct AS_Query));
        as_query->as_table  = as_table_v4;
        as_query->as6_table = as_table_v6;
    }

    return as_query;
}

static const struct AS_Info _search_ipv4(const struct AS_Table *as_table,
                                         const ipv4address      ip) {
    if (as_table == NULL)
        goto err0;

    unsigned maxmax = as_table->list_len;
    unsigned min    = 0;
    unsigned max    = as_table->list_len;
    unsigned mid;

    /**
     * Do binary search
     */
    for (;;) {
        mid = min + (max - min) / 2;
        if (ip < as_table->list[mid].begin) {
            if (max == mid)
                break;
            max = mid;
            continue;
        } else if (ip > as_table->list[mid].end) {
            if (mid + 1 == maxmax)
                break;
            else if (ip < as_table->list[mid + 1].begin)
                break;
            else
                min = mid + 1;
        } else {
            return as_table->list[mid].as_info;
        }
    }

err0:; /*compatible to low version gcc*/

    struct AS_Info nul_info = {
        .asn = 0, .country_code = "(null)", .desc = "(null)"};

    return nul_info;
}

static const struct AS_Info _search_ipv6(const struct AS6_Table *as6_table,
                                         const ipv6address       ip) {
    if (as6_table == NULL)
        goto err0;

    unsigned maxmax = as6_table->list_len;
    unsigned min    = 0;
    unsigned max    = as6_table->list_len;
    unsigned mid;

    /**
     * Do binary search
     */
    for (;;) {
        mid = min + (max - min) / 2;
        if (ipv6address_is_lessthan(ip, as6_table->list[mid].begin)) {
            if (max == mid)
                break;
            max = mid;
            continue;
        } else if (ipv6address_is_lessthan(as6_table->list[mid].end, ip)) {
            if (mid + 1 == maxmax)
                break;
            else if (ipv6address_is_lessthan(ip,
                                             as6_table->list[mid + 1].begin))
                break;
            else
                min = mid + 1;
        } else {
            return as6_table->list[mid].as_info;
        }
    }

err0:; /*compatible to low version gcc*/

    struct AS_Info nul_info = {
        .asn = 0, .country_code = "(null)", .desc = "(null)"};

    return nul_info;
}

const struct AS_Info as_query_search_ip(const struct AS_Query *as_query,
                                        const ipaddress        ip) {
    if (ip.version == 4) {
        return _search_ipv4(as_query->as_table, ip.ipv4);
    } else {
        return _search_ipv6(as_query->as6_table, ip.ipv6);
    }
}

bool as_query_add_as_to_range(const struct AS_Query *as_query,
                              struct RangeList *ipv4_list, unsigned asn) {
    bool added = false;
    if (as_query->as_table == NULL) {
        LOG(LEVEL_WARN, "(%s) no ipv4 AS info loaded.\n", __func__);
        return added;
    }

    struct AS_Table *as_table = as_query->as_table;
    for (uint64_t i = 0; i < as_table->list_len; i++) {

        if (as_table->list[i].as_info.asn == asn) {
            added = true;
            rangelist_add_range(ipv4_list, as_table->list[i].begin,
                                as_table->list[i].end);
        }
    }

    if (!added) {
        LOG(LEVEL_WARN, "no ipv4 AS info for AS%u.\n", asn);
    }

    return added;
}

bool as_query_add_as_to_range6(const struct AS_Query *as_query,
                               struct Range6List *ipv6_list, unsigned asn) {
    bool added = false;
    if (as_query->as6_table == NULL) {
        LOG(LEVEL_WARN, "(%s) no ipv6 AS info loaded.\n", __func__);
        return added;
    }

    struct AS6_Table *as6_table = as_query->as6_table;
    for (uint64_t i = 0; i < as6_table->list_len; i++) {

        if (as6_table->list[i].as_info.asn == asn) {
            added = true;
            range6list_add_range(ipv6_list, as6_table->list[i].begin,
                                 as6_table->list[i].end);
        }
    }

    if (!added) {
        LOG(LEVEL_WARN, "no ipv6 AS info for AS%u.\n", asn);
    }

    return added;
}

void as_query_destroy(struct AS_Query *as_query) {
    if (as_query == NULL) {
        return;
    }

    if (as_query->as_table) {
        for (uint64_t i = 0; i < as_query->as_table->list_len; i++) {
            FREE(as_query->as_table->list[i].as_info.country_code);
            FREE(as_query->as_table->list[i].as_info.desc);
        }
        FREE(as_query->as_table);
    }

    if (as_query->as6_table) {
        for (uint64_t i = 0; i < as_query->as6_table->list_len; i++) {
            FREE(as_query->as6_table->list[i].as_info.country_code);
            FREE(as_query->as6_table->list[i].as_info.desc);
        }
        FREE(as_query->as6_table);
    }
}