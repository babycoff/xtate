#include "output-modules.h"

#include "../xconf.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../pixie/pixie-file.h"

extern Output CsvOutput; /*for internal x-ref*/

static FILE *file;

static const char header_csv[]             = "time,"
                                             "level,"
                                             "ip_proto,"
                                             "ip_them,"
                                             "port_them,"
                                             "ip_me,"
                                             "port_me,"
                                             "classification,"
                                             "reason,"
                                             "scan report,"
                                             "probe report,"
                                             "output report"
                                             "\n";
static const char fmt_csv_prefix[]         = "%s,"
                                             "%s,"
                                             "%s,"
                                             "%s,"
                                             "%u,"
                                             "%s,"
                                             "%u,"
                                             "%s,"
                                             "%s,"
                                             "\"{";
static const char fmt_csv_prefix_no_port[] = "%s,"
                                             "%s,"
                                             "%s,"
                                             "%s,"
                                             ","
                                             "%s,"
                                             ","
                                             "%s,"
                                             "%s,"
                                             "\"{";
static const char fmt_csv_str_inffix[]     = ",\"\"%s\"\":\"\"%s\"\"";
static const char fmt_csv_bin_inffix[] = ",\"\"%s\"\":\"\"(%u bytes bin)\"\"";
static const char fmt_csv_int_inffix[] = ",\"\"%s\"\":%" PRIu64;
static const char fmt_csv_double_inffix[] = ",\"\"%s\"\":%.2f";
static const char fmt_csv_true_inffix[]   = ",\"\"%s\"\":true";
static const char fmt_csv_false_inffix[]  = ",\"\"%s\"\":false";
static const char fmt_csv_inffix[]        = "}\",\"{";
static const char fmt_csv_suffix[]        = "}\""
                                            "\n";

static char format_time[32];

static bool csv_init(const XConf *xconf, const OutConf *out) {
    /*a convention*/
    if (out->output_filename[0] == '-' && strlen(out->output_filename) == 1) {
        file = stdout;
        return true;
    }

    int err =
        pixie_fopen_shareable(&file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "(CsvOutput) could not open file %s for %s.\n",
            out->output_filename, out->is_append ? "appending" : "writing");
        LOGPERROR(out->output_filename);
        return false;
    }

    if (!out->is_append) {
        err = fputs(header_csv, file);
        if (err < 0)
            LOG(LEVEL_ERROR, "(CsvOutput) could not write header to file.\n");
    }

    return true;
}

static void csv_result(OutItem *item) {
    unsigned  is_first;
    DataLink *pre;
    int       err = 0;

    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);

    safe_iso8601_time(format_time, sizeof(format_time), &item->timestamp);

    if (item->no_port) {
        err = fprintf(file, fmt_csv_prefix_no_port, format_time,
                      output_level_to_string(item->level),
                      ip_proto_to_string(item->target.ip_proto),
                      ip_them_fmt.string, ip_me_fmt.string,
                      item->classification, item->reason);
    } else {
        err = fprintf(file, fmt_csv_prefix, format_time,
                      output_level_to_string(item->level),
                      ip_proto_to_string(item->target.ip_proto),
                      ip_them_fmt.string, item->target.port_them,
                      ip_me_fmt.string, item->target.port_me,
                      item->classification, item->reason);
    }

    if (err < 0)
        goto error;

    pre      = item->scan_report.link;
    is_first = 1; /*no comma for first item*/
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            err = fprintf(file, fmt_csv_str_inffix + is_first, pre->next->name,
                          pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            err = fprintf(file, fmt_csv_int_inffix + is_first, pre->next->name,
                          pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            err = fprintf(file, fmt_csv_double_inffix + is_first,
                          pre->next->name, pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            err =
                fprintf(file,
                        pre->next->value_bool ? fmt_csv_true_inffix + is_first
                                              : fmt_csv_false_inffix + is_first,
                        pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            err = fprintf(file, fmt_csv_bin_inffix + is_first, pre->next->name,
                          pre->next->data_len);
        }

        if (err < 0)
            goto error;

        pre      = pre->next;
        is_first = 0;
    }

    err = fprintf(file, fmt_csv_inffix);
    if (err < 0)
        goto error;

    pre      = item->probe_report.link;
    is_first = 1; /*no comma for first item*/
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            err = fprintf(file, fmt_csv_str_inffix + is_first, pre->next->name,
                          pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            err = fprintf(file, fmt_csv_int_inffix + is_first, pre->next->name,
                          pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            err = fprintf(file, fmt_csv_double_inffix + is_first,
                          pre->next->name, pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            err =
                fprintf(file,
                        pre->next->value_bool ? fmt_csv_true_inffix + is_first
                                              : fmt_csv_false_inffix + is_first,
                        pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            err = fprintf(file, fmt_csv_bin_inffix + is_first, pre->next->name,
                          pre->next->data_len);
        }

        if (err < 0)
            goto error;

        pre      = pre->next;
        is_first = 0;
    }

    err = fprintf(file, fmt_csv_inffix);
    if (err < 0)
        goto error;

    pre      = item->output_report.link;
    is_first = 1; /*no comma for first item*/
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            err = fprintf(file, fmt_csv_str_inffix + is_first, pre->next->name,
                          pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            err = fprintf(file, fmt_csv_int_inffix + is_first, pre->next->name,
                          pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            err = fprintf(file, fmt_csv_double_inffix + is_first,
                          pre->next->name, pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            err =
                fprintf(file,
                        pre->next->value_bool ? fmt_csv_true_inffix + is_first
                                              : fmt_csv_false_inffix + is_first,
                        pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            err = fprintf(file, fmt_csv_bin_inffix + is_first, pre->next->name,
                          pre->next->data_len);
        }

        if (err < 0)
            goto error;

        pre      = pre->next;
        is_first = 0;
    }

    err = fprintf(file, fmt_csv_suffix);
    if (err < 0)
        goto error;

    return;

error:
    LOG(LEVEL_ERROR, "(CsvOutput) could not write result to file.\n");
}

static void csv_close(const OutConf *out) {
    if (fflush(file) != 0)
        LOG(LEVEL_ERROR, "(CsvOutput) could not flush output file.\n");
    if (file != stdout && fclose(file) != 0)
        LOG(LEVEL_ERROR, "(CsvOutput) could not close output file.\n");
}

Output CsvOutput = {
    .name       = "csv",
    .need_file  = true,
    .params     = NULL,
    .short_desc = "Save results in CSV(Comma-Separated Values) format.",
    .desc = "CsvOutput save results in Comma-Seperated Values(csv) format to "
            "specified file.\n"
            "NOTE: CsvOutput doesn't convert any escaped chars actively.",

    .init_cb   = &csv_init,
    .result_cb = &csv_result,
    .close_cb  = &csv_close,
};