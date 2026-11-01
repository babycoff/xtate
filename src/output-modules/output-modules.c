#include "output-modules.h"

#include <stdio.h>
#include <string.h>

#include "../xconf.h"
#include "../globals.h"
#include "../pixie/pixie-threads.h"
#include "../util-out/logger.h"
#include "../util-out/xprint.h"
#include "../util-misc/misc.h"

static volatile int _output_fatal_error = 0;

// clang-format off
extern Output TextOutput;
extern Output NdjsonOutput;
#ifndef NOT_FOUND_BSON
extern Output BsonOutput;
#endif
extern Output CsvOutput;
extern Output ListOutput;
extern Output NullOutput;
#ifndef NOT_FOUND_MONGOC
extern Output MongodbOutput;
#endif
//! ADD YOUR OUTPUT MODULE HERE


Output *output_modules_list[] = {
    &TextOutput,
    &NdjsonOutput,
#ifndef NOT_FOUND_BSON
    &BsonOutput,
#endif
    &CsvOutput,
    &ListOutput,
#ifndef NOT_FOUND_MONGOC
    &MongodbOutput,
#endif
    &NullOutput,
    //! REGISTER YOUR OUTPUT MODULE HERE

    NULL /*keep the null tail*/
};
// clang-format on

const char *output_level_to_string(OutLevel level) {
    switch (level) {
        case OUT_INFO:
            return "information";
        case OUT_FAILURE:
            return "failure";
        case OUT_SUCCESS:
            return "success";

        default:
            return "unknown";
    }
}

Output *get_output_module_by_name(const char *name) {
    int len = (int)ARRAY_SIZE(output_modules_list) - 1;
    for (int i = 0; i < len; i++) {
        if (conf_equals(output_modules_list[i]->name, name)) {
            return output_modules_list[i];
        }
    }
    return NULL;
}

void list_searched_output_modules(const char *name) {
    int len = (int)(ARRAY_SIZE(output_modules_list)) - 1;
    int distance;
    for (int i = 0; i < len; i++) {
        distance = conf_fuzzy_distance(output_modules_list[i]->name, name);
        if (distance < 0) {
            LOG(LEVEL_ERROR, "(%s) failed to matching.\n", __func__);
            break;
        }
        if (distance <= 2) {
            printf("    %s -> %s\n", output_modules_list[i]->name,
                   output_modules_list[i]->short_desc
                       ? output_modules_list[i]->short_desc
                       : output_modules_list[i]->desc);
        }
    }
}

void list_all_output_modules() {
    int len = (int)(ARRAY_SIZE(output_modules_list)) - 1;

    printf("\n");

    for (int i = 0; i < len; i++) {
        printf("  %d.%s\n", i + 1, output_modules_list[i]->name);
        printf("    %s\n", output_modules_list[i]->short_desc
                               ? output_modules_list[i]->short_desc
                               : output_modules_list[i]->desc);
        printf("\n");
    }
}

void help_output_module(Output *module) {
    if (!module) {
        LOG(LEVEL_ERROR, "no specified output module.\n");
        return;
    }

    printf("\n");
    printf("  Name of OutputModule: %s\n", module->name);
    printf("  Need to Specify file: %s\n",
           module->need_file ? "true" : "false");
    printf("\n");
    printf("  Description:\n");
    xprint(module->desc, 6, 80);
    printf("\n");
    printf("\n");
    if (module->params) {
        for (unsigned j = 0; module->params[j].name; j++) {
            if (!module->params[j].help_text)
                continue;

            printf("  --%s", module->params[j].name);
            for (unsigned k = 0; module->params[j].alt_names[k]; k++) {
                printf(", %s", module->params[j].alt_names[k]);
            }
            printf("\n");
            xprint(module->params[j].help_text, 6, 80);
            printf("\n\n");
        }
    }

    printf("\n");
}

static const char fmt_host[]          = "%s host: %-15s";
static const char fmt_port[]          = " port: %-5u";
static const char fmt_cls[]           = " \"%s\"";
static const char fmt_reason[]        = " because \"%s\"";
static const char fmt_report_str[]    = ",  %s: \"%s\"";
static const char fmt_report_bin[]    = ",  %s: \"(%u bytes bin)\"";
static const char fmt_report_int[]    = ",  %s: %" PRIu64;
static const char fmt_report_double[] = ", %s: %.2f";
static const char fmt_report_true[]   = ", %s: true";
static const char fmt_report_false[]  = ", %s: false";

static bool _output_ansi;

bool output_init(const XConf *xconf, OutConf *out_conf) {
    if (out_conf->output_as_info && !out_conf->as_query) {
        LOG(LEVEL_ERROR, "cannot output AS info to scan results because no "
                         "ip2asn files are specified.\n");
        LOG(LEVEL_HINT,
            "load AS info by specifying --ip2asn-v4 or/and --ip2asn-v6.\n");
        return false;
    }

    if (out_conf->output_module) {
        if (out_conf->output_module->need_file &&
            !out_conf->output_filename[0]) {
            LOG(LEVEL_ERROR,
                "OutputModule %s need to specify output file name by "
                "`--output-file`.\n",
                out_conf->output_module->name);
            return false;
        }

        if (out_conf->output_module->params && out_conf->output_args &&
            out_conf->output_args[0]) {
            if (conf_set_params_from_substr(NULL,
                                            out_conf->output_module->params,
                                            out_conf->output_args)) {
                LOG(LEVEL_ERROR, "sub param parsing of OutputModule.\n");
                return false;
            }
        }

        if (!out_conf->output_module->init_cb(xconf, out_conf)) {
            return false;
        }
    }

    _output_ansi = !xconf->is_no_ansi;

    out_conf->stdout_mutex = pixie_create_mutex();
    out_conf->module_mutex = pixie_create_mutex();

    return true;
}

/*Some special processes should be done when output to stdout for avoiding
 * mess*/
void output_mark_fatal(void) { _output_fatal_error = 1; }

bool output_has_fatal_error(void) { return _output_fatal_error != 0; }

static void output_result_to_stdout(OutItem *item) {
    // ipaddress_formatted_t ip_me_fmt = ipaddress_fmt(item->target.ip_me);
    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);

    unsigned  count = 0;
    DataLink *pre;

    if (_output_ansi) {
        fprintf(stdout, XPRINT_CLEAR_LINE);

        switch (item->level) {
            case OUT_SUCCESS:
                count = fprintf(stdout, XPRINT_CH_COLOR_GREEN);
                break;
            case OUT_FAILURE:
                count = fprintf(stdout, XPRINT_CH_COLOR_RED);
                break;
            case OUT_INFO:
                count = fprintf(stdout, XPRINT_CH_COLOR_CYAN);
                break;
            default:
                break;
        }
    }

    switch (item->level) {
        case OUT_SUCCESS:
            count = fprintf(stdout, fmt_host, "[+]", ip_them_fmt.string);
            break;
        case OUT_FAILURE:
            count = fprintf(stdout, fmt_host, "[x]", ip_them_fmt.string);
            break;
        case OUT_INFO:
            count = fprintf(stdout, fmt_host, "[*]", ip_them_fmt.string);
            break;
        default:
            count = fprintf(stdout, fmt_host, "[?]", ip_them_fmt.string);
    }

    if (!item->no_port) {
        count += fprintf(stdout, fmt_port, item->target.port_them);
    }

    if (item->classification[0]) {
        count += fprintf(stdout, fmt_cls, item->classification);
    }

    if (item->reason[0]) {
        count += fprintf(stdout, fmt_reason, item->reason);
    }

    if (_output_ansi)
        fprintf(stdout, XPRINT_CH_COLOR_YELLOW);

    pre = item->scan_report.link;
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            count += fprintf(stdout, fmt_report_str, pre->next->name,
                             pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            count += fprintf(stdout, fmt_report_int, pre->next->name,
                             pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            count += fprintf(stdout, fmt_report_double, pre->next->name,
                             pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            count += fprintf(stdout,
                             pre->next->value_bool ? fmt_report_true
                                                   : fmt_report_false,
                             pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            count += fprintf(stdout, fmt_report_bin, pre->next->name,
                             pre->next->data_len);
        }

        pre = pre->next;
    }

    pre = item->probe_report.link;
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            count += fprintf(stdout, fmt_report_str, pre->next->name,
                             pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            count += fprintf(stdout, fmt_report_int, pre->next->name,
                             pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            count += fprintf(stdout, fmt_report_double, pre->next->name,
                             pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            count += fprintf(stdout,
                             pre->next->value_bool ? fmt_report_true
                                                   : fmt_report_false,
                             pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            count += fprintf(stdout, fmt_report_bin, pre->next->name,
                             pre->next->data_len);
        }

        pre = pre->next;
    }

    pre = item->output_report.link;
    while (pre->next) {
        if (pre->next->link_type == LinkType_String) {
            count += fprintf(stdout, fmt_report_str, pre->next->name,
                             pre->next->value_data);
        } else if (pre->next->link_type == LinkType_Int) {
            count += fprintf(stdout, fmt_report_int, pre->next->name,
                             pre->next->value_int);
        } else if (pre->next->link_type == LinkType_Double) {
            count += fprintf(stdout, fmt_report_double, pre->next->name,
                             pre->next->value_double);
        } else if (pre->next->link_type == LinkType_Bool) {
            count += fprintf(stdout,
                             pre->next->value_bool ? fmt_report_true
                                                   : fmt_report_false,
                             pre->next->name);
        } else if (pre->next->link_type == LinkType_Binary) {
            count += fprintf(stdout, fmt_report_bin, pre->next->name,
                             pre->next->data_len);
        }

        pre = pre->next;
    }

    if (_output_ansi)
        fprintf(stdout, XPRINT_RESET);
    else if (count < 120)
        fprintf(stdout, "%*s", (int)(120 - count), "");

    fprintf(stdout, "\n");
    fflush(stdout);
}

void output_result(const OutConf *out, OutItem *item) {
    if (item->no_output)
        goto error0;

    if (!item->timestamp)
        ((OutItem *)item)->timestamp = global_get_time();

    if (item->level == OUT_SUCCESS) {
        pixie_locked_add_u64(&((OutConf *)out)->total_successed, 1);
    }

    if (item->level == OUT_FAILURE) {
        pixie_locked_add_u64(&((OutConf *)out)->total_failed, 1);
    }

    if (item->level == OUT_INFO) {
        pixie_locked_add_u64(&((OutConf *)out)->total_info, 1);
    }

    if (item->level == OUT_INFO && !out->is_show_info)
        goto error0;
    if (item->level == OUT_FAILURE && !out->is_show_failed)
        goto error0;
    if (item->level == OUT_SUCCESS && out->no_show_success)
        goto error0;

    if (out->output_as_info) {
        struct AS_Info as_info =
            as_query_search_ip(out->as_query, item->target.ip_them);
        dach_append_str(&item->output_report, "AS desc", as_info.desc,
                        strlen(as_info.desc));
        dach_append_str(&item->output_report, "AS country code",
                        as_info.country_code, strlen(as_info.country_code));
        dach_set_int(&item->output_report, "ASN", as_info.asn);
    }

    if (out->output_module) {
        pixie_acquire_mutex(out->module_mutex);
        out->output_module->result_cb(item);
        pixie_release_mutex(out->module_mutex);
        if (out->is_out_screen) {
            pixie_acquire_mutex(out->stdout_mutex);
            output_result_to_stdout(item);
            pixie_release_mutex(out->stdout_mutex);
        }
    } else {
        pixie_acquire_mutex(out->stdout_mutex);
        output_result_to_stdout(item);
        pixie_release_mutex(out->stdout_mutex);
    }

error0:
    dach_release(&item->scan_report);
    dach_release(&item->probe_report);
    dach_release(&item->output_report);
}

void output_close(OutConf *out_conf) {
    if (out_conf->output_module) {
        out_conf->output_module->close_cb(out_conf);
    }

    pixie_delete_mutex(out_conf->stdout_mutex);
    pixie_delete_mutex(out_conf->module_mutex);
}

bool output_init_nothing(const XConf *xconf, const OutConf *out_conf) {
    return true;
}

void output_result_nothing(OutItem *item) {}

void output_close_nothing(const OutConf *out_conf) {}