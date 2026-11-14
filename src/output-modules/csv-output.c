#include "output-modules.h"
#include "output-write.h"

#include "../xconf.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-data/json-escape.h"
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

static void csv_field(FILE *fp, const char *value) {
    out_fputc('"', fp);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"')
            fputs("\"\"", fp);
        else
            out_fputc(*p, fp);
    }
    out_fputc('"', fp);
}

static void csv_json_sink(void *ctx, const char *data, size_t len) {
    FILE *fp = (FILE *)ctx;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '"')
            fputs("\"\"", fp);
        else
            out_fputc(data[i], fp);
    }
}

/* Write a JSON string while keeping the surrounding CSV field valid. */
static void csv_json_string(FILE *fp, const char *value, size_t len) {
    fputs("\"\"", fp);
    json_escape_to(csv_json_sink, fp, (const unsigned char *)value, len);
    fputs("\"\"", fp);
}

static void csv_report(FILE *fp, DataChain *chain) {
    DataLink *pre = chain->link;
    out_fputc('"', fp);
    out_fputc('{', fp);
    unsigned first = 1;
    while (pre->next) {
        DataLink *l = pre->next;
        if (!first)
            out_fputc(',', fp);
        first = 0;
        csv_json_string(fp, l->name, strlen(l->name));
        out_fputc(':', fp);
        switch (l->link_type) {
            case LinkType_String:
                csv_json_string(fp, (const char *)l->value_data,
                                strnlen((const char *)l->value_data,
                                        l->data_len));
                break;
            case LinkType_Int:
                out_fprintf(fp, "%" PRIu64, l->value_int);
                break;
            case LinkType_Double:
                out_fprintf(fp, "%.2f", l->value_double);
                break;
            case LinkType_Bool:
                fputs(l->value_bool ? "true" : "false", fp);
                break;
            case LinkType_Binary:
                out_fprintf(fp, "\"(%u bytes bin)\"", l->data_len);
                break;
            default:
                fputs("null", fp);
        }
        pre = l;
    }
    out_fputc('}', fp);
    out_fputc('"', fp);
}

static void csv_result(OutItem *item) {
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);

    safe_iso8601_time(format_time, sizeof(format_time), &item->timestamp);

    csv_field(file, format_time);
    out_fputc(',', file);
    csv_field(file, output_level_to_string(item->level));
    out_fputc(',', file);
    csv_field(file, ip_proto_to_string(item->target.ip_proto));
    out_fputc(',', file);
    csv_field(file, ip_them_fmt.string);
    out_fputc(',', file);
    if (!item->no_port)
        out_fprintf(file, "%u", item->target.port_them);
    out_fputc(',', file);
    csv_field(file, ip_me_fmt.string);
    out_fputc(',', file);
    if (!item->no_port)
        out_fprintf(file, "%u", item->target.port_me);
    out_fputc(',', file);
    csv_field(file, item->classification);
    out_fputc(',', file);
    csv_field(file, item->reason);
    out_fputc(',', file);
    csv_report(file, &item->scan_report);
    out_fputc(',', file);
    csv_report(file, &item->probe_report);
    out_fputc(',', file);
    csv_report(file, &item->output_report);
    out_fputc('\n', file);

    if (ferror(file))
        output_error("CsvOutput", "could not write result to file.");
}

static void csv_close(const OutConf *out) {
    if (fflush(file) != 0)
        output_error("CsvOutput", "could not flush output file.");
    if (file != stdout && fclose(file) != 0)
        output_error("CsvOutput", "could not close output file.");
}

Output CsvOutput = {
    .name       = "csv",
    .need_file  = true,
    .params     = NULL,
    .short_desc = "Save results in CSV(Comma-Separated Values) format.",
    .desc = "CsvOutput save results in Comma-Separated Values(csv) format to "
            "specified file.\n"
            "NOTE: CsvOutput doesn't convert any escaped chars actively.",

    .init_cb   = &csv_init,
    .result_cb = &csv_result,
    .close_cb  = &csv_close,
};