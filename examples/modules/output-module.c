#include "../../src/output-modules/output-modules.h"
#include "../../src/target/target-ipaddress.h"
#include "../../src/util-data/data-chain.h"
#include "../../src/util-misc/misc.h"

#include <stdio.h>
#include <string.h>

static FILE *example_file = NULL;

static bool example_out_init(const struct XtateConf *xconf,
                             const OutConf *out) {
    UNUSEDPARM(xconf);
    if (strcmp(out->output_filename, "-") == 0) {
        example_file = stdout;
        return true;
    }
    example_file = fopen(out->output_filename, "w");
    return example_file != NULL;
}

static void example_out_result(OutItem *item) {
    ipaddress_formatted_t ip = ipaddress_fmt(item->target.ip_them);
    fprintf(example_file, "%s\t%u\t%s\t%s\n", ip.string,
            item->target.port_them, item->classification, item->reason);

    DataLink *link = item->probe_report.link;
    while (link->next) {
        link = link->next;
        if (link->link_type == LinkType_String) {
            fprintf(example_file, "\t%s=%s", link->name, link->value_data);
        } else if (link->link_type == LinkType_Int) {
            fprintf(example_file, "\t%s=%llu", link->name,
                    (unsigned long long)link->value_int);
        }
    }
    fputc('\n', example_file);
    fflush(example_file);
}

static void example_out_close(const OutConf *out) {
    UNUSEDPARM(out);
    if (example_file && example_file != stdout)
        fclose(example_file);
    example_file = NULL;
}

Output ExampleOutput = {
    .name = "example-output",
    .need_file = true,
    .desc = "Compile-tested output-module template.",
    .init_cb = &example_out_init,
    .result_cb = &example_out_result,
    .close_cb = &example_out_close,
};

