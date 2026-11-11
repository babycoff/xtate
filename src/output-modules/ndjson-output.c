#include "output-modules.h"
#include "output-write.h"

#include "../xconf.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-data/json-escape.h"
#include "../pixie/pixie-file.h"

extern Output NdjsonOutput; /*for internal x-ref*/

static FILE *file;

static const char fmt_ndjson_prefix[]        = "{"
                                               "\"time\":\"%s\","
                                               "\"level\":\"%s\","
                                               "\"ip_proto\":\"%s\","
                                               "\"ip_them\":\"%s\",";
static const char fmt_ndjson_port_them[]     = "\"port_them\":%u,";
static const char fmt_ndjson_ip_me[]         = "\"ip_me\":\"%s\",";
static const char fmt_ndjson_port_me[]       = "\"port_me\":%u,";
static const char fmt_ndjson_inffix[]        = "\"classification\":\"%s\","
                                               "\"reason\":\"%s\"";
static const char fmt_ndjson_scan_inffix[]   = ",\"scan report\":{";
static const char fmt_ndjson_probe_inffix[]  = ",\"probe report\":{";
static const char fmt_ndjson_output_inffix[] = ",\"output report\":{";
static const char fmt_ndjson_str_inffix[]    = ",\"%s\":\"%s\"";
static const char fmt_ndjson_bin_inffix[]    = ",\"%s\":\"(%u bytes bin)\"";
static const char fmt_ndjson_int_inffix[]    = ",\"%s\":%" PRIu64;
static const char fmt_ndjson_double_inffix[] = ",\"%s\":%.2f";
static const char fmt_ndjson_true_inffix[]   = ",\"%s\":true";
static const char fmt_ndjson_false_inffix[]  = ",\"%s\":false";

static char format_time[32];

static bool ndjson_init(const XConf *xconf, const OutConf *out) {
    /*a convention*/
    if (out->output_filename[0] == '-' && strlen(out->output_filename) == 1) {
        file = stdout;
        return true;
    }

    int err =
        pixie_fopen_shareable(&file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "(NdjsonOutput) could not open file %s for %s.\n",
            out->output_filename, out->is_append ? "appending" : "writing");
        LOGPERROR(out->output_filename);
        return false;
    }

    return true;
}

static void ndjson_file_sink(void *ctx, const char *data, size_t len) {
    out_fwrite(data, 1, len, (FILE *)ctx);
}

static void ndjson_quote(FILE *fp, const char *s, size_t len) {
    out_fputc('"', fp);
    json_escape_to(ndjson_file_sink, fp, (const unsigned char *)s, len);
    out_fputc('"', fp);
}

static void ndjson_key(FILE *fp, unsigned *first, const char *name) {
    if (!*first)
        out_fputc(',', fp);
    *first = 0;
    ndjson_quote(fp, name, strlen(name));
    out_fputc(':', fp);
}

static void ndjson_str(FILE *fp, const char *name, const char *value) {
    unsigned first = 0;
    ndjson_key(fp, &first, name);
    ndjson_quote(fp, value, strlen(value));
}

static void ndjson_result(OutItem *item) {
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
    ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);
    safe_iso8601_time(format_time, sizeof(format_time), &item->timestamp);

    out_fputc('{', file);
    fputs("\"time\":", file);
    ndjson_quote(file, format_time, strlen(format_time));
    fputs(",\"level\":", file);
    ndjson_quote(file, output_level_to_string(item->level),
                 strlen(output_level_to_string(item->level)));
    fputs(",\"ip_proto\":", file);
    const char *proto = ip_proto_to_string(item->target.ip_proto);
    ndjson_quote(file, proto, strlen(proto));
    fputs(",\"ip_them\":", file);
    ndjson_quote(file, ip_them_fmt.string, strlen(ip_them_fmt.string));
    if (!item->no_port)
        out_fprintf(file, ",\"port_them\":%u", item->target.port_them);
    fputs(",\"ip_me\":", file);
    ndjson_quote(file, ip_me_fmt.string, strlen(ip_me_fmt.string));
    if (!item->no_port)
        out_fprintf(file, ",\"port_me\":%u", item->target.port_me);
    fputs(",\"classification\":", file);
    ndjson_quote(file, item->classification,
                 strnlen(item->classification, OUT_CLS_SIZE));
    fputs(",\"reason\":", file);
    ndjson_quote(file, item->reason, strnlen(item->reason, OUT_RSN_SIZE));

    const char *sections[] = {"scan report", "probe report", "output report"};
    DataChain *chains[] = {&item->scan_report, &item->probe_report,
                           &item->output_report};
    for (unsigned k = 0; k < 3; k++) {
        DataLink *pre = chains[k]->link;
        if (!pre->next)
            continue;
        fputs(",\"", file);
        fputs(sections[k], file);
        fputs("\":{", file);
        unsigned first = 1;
        while (pre->next) {
            DataLink *l = pre->next;
            if (!first)
                out_fputc(',', file);
            first = 0;
            ndjson_quote(file, l->name, strlen(l->name));
            out_fputc(':', file);
            switch (l->link_type) {
                case LinkType_String:
                    ndjson_quote(file, (const char *)l->value_data,
                                 strnlen((const char *)l->value_data,
                                         l->data_len));
                    break;
                case LinkType_Int:
                    out_fprintf(file, "%" PRIu64, l->value_int);
                    break;
                case LinkType_Double:
                    out_fprintf(file, "%.2f", l->value_double);
                    break;
                case LinkType_Bool:
                    fputs(l->value_bool ? "true" : "false", file);
                    break;
                case LinkType_Binary:
                    out_fprintf(file, "\"(%u bytes bin)\"", l->data_len);
                    break;
                default:
                    fputs("null", file);
            }
            pre = l;
        }
        out_fputc('}', file);
    }
    fputs("}\n", file);

    if (ferror(file))
        output_error("NdjsonOutput", "could not write result to file.");
}

static void ndjson_close(const OutConf *out) {
    if (fflush(file) != 0)
        output_error("NdjsonOutput", "could not flush output file.");
    if (file != stdout && fclose(file) != 0)
        output_error("NdjsonOutput", "could not close output file.");
}

Output NdjsonOutput = {
    .name       = "ndjson",
    .need_file  = true,
    .params     = NULL,
    .short_desc = "Save results in NDJSON format.",
    .desc =
        "NdjsonOutput save results in Newline-Delimited JSON(NDJSON) format to "
        "specified file. The format is also called JSONL(ines) and its filename"
        " suffix can be '.jsonl'.\n"
        "Strings are JSON-escaped on output. Values that were already normalized "
        "to \\xNN form are emitted as literal JSON strings, not decoded bytes.",

    .init_cb   = &ndjson_init,
    .result_cb = &ndjson_result,
    .close_cb  = &ndjson_close,
};