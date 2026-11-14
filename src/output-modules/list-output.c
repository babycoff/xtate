#include "output-modules.h"
#include "output-write.h"

#include <string.h>

#include "../xconf.h"
#include "../util-misc/misc.h"
#include "../pixie/pixie-file.h"
#include "../util-out/logger.h"

static const char fmt_host[] = "%s";
static const char fmt_port[] = " %s%u";

extern Output ListOutput; /*for internal x-ref*/

static FILE *file;

struct ListConf {
    unsigned no_port : 1;
};

static struct ListConf list_conf = {0};

static ConfRes SET_no_port(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    list_conf.no_port = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam list_parameters[] = {
    {"no-port",
     SET_no_port,
     Type_FLAG,
     {0},
     "Just output the IP list.\n"
     "NOTE: No deduplicating will be used for IP."},
    {0}};

static bool list_init(const XConf *xconf, const OutConf *out) {
    /*a convention*/
    if (out->output_filename[0] == '-' && strlen(out->output_filename) == 1) {
        file = stdout;
        return true;
    }

    int err =
        pixie_fopen_shareable(&file, out->output_filename, out->is_append);

    if (err != 0 || file == NULL) {
        LOG(LEVEL_ERROR, "(ListOutput) could not open file %s for %s.\n",
            out->output_filename, out->is_append ? "appending" : "writing");
        LOGPERROR(out->output_filename);
        return false;
    }

    return true;
}

static void list_result(OutItem *item) {
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);

    int err = out_fprintf(file, fmt_host, ip_them_fmt.string);

    if (err < 0)
        goto error;

    if (!item->no_port && !list_conf.no_port) {
        switch (item->target.ip_proto) {
            case IP_PROTO_TCP:
                err = out_fprintf(file, fmt_port, "", item->target.port_them);
                break;
            case IP_PROTO_UDP:
                err = out_fprintf(file, fmt_port, "u:", item->target.port_them);
                break;
            case IP_PROTO_SCTP:
                err = out_fprintf(file, fmt_port, "s:", item->target.port_them);
                break;
            default:
                err = out_fprintf(file, fmt_port, "o:", item->target.port_them);
                break;
        }
        if (err < 0)
            goto error;
    }

    err = out_fprintf(file, "\n");
    if (err < 0)
        goto error;

    return;

error:
    output_error("ListOutput", "could not write result to file.");
}

static void list_close(const OutConf *out) {
    if (fflush(file) != 0)
        output_error("ListOutput", "could not flush output file.");
    if (file != stdout && fclose(file) != 0)
        output_error("ListOutput", "could not close output file.");
}

Output ListOutput = {
    .name       = "list",
    .need_file  = true,
    .params     = list_parameters,
    .short_desc = "Save IP(Port) list of results.",
    .desc =
        "ListOutput save results just in \"IP port\" format to specified file "
        "without any other information.",

    .init_cb   = &list_init,
    .result_cb = &list_result,
    .close_cb  = &list_close,
};