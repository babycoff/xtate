#include "generate-modules.h"
#include "../util-misc/i18n.h"

#include <stdio.h>

#include "../xconf.h"
#include "../util-out/xprint.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

// clang-format off
extern Generator BlackRockGen;
extern Generator IpStreamGen;
extern Generator AddrStreamGen;
extern Generator IpListGen;
extern Generator AddrListGen;
//! ADD YOUR GENERATE MODULE HERE


Generator *generate_modules_list[] = {
    &BlackRockGen, /* its also the default generator*/
    &IpStreamGen,
    &AddrStreamGen,
    &IpListGen,
    &AddrListGen,
    //! REGISTER YOUR GENERATE MODULE HERE

    NULL /*keep the null tail*/
};
// clang-format on

Generator *get_generate_module_by_name(const char *name) {
    int len = (int)ARRAY_SIZE(generate_modules_list) - 1;
    for (int i = 0; i < len; i++) {
        if (conf_equals(generate_modules_list[i]->name, name)) {
            return generate_modules_list[i];
        }
    }
    return NULL;
}

void list_searched_generate_modules(const char *name) {
    int len = (int)(ARRAY_SIZE(generate_modules_list)) - 1;
    int distance;
    for (int i = 0; i < len; i++) {
        distance = conf_fuzzy_distance(generate_modules_list[i]->name, name);
        if (distance < 0) {
            LOG(LEVEL_ERROR, "(%s) failed to matching.\n", __func__);
            break;
        }
        if (distance <= 2) {
            printf("    %s -> %s\n", generate_modules_list[i]->name,
                   generate_modules_list[i]->short_desc
                       ? generate_modules_list[i]->short_desc
                       : generate_modules_list[i]->desc);
        }
    }
}

void list_all_generate_modules() {
    int len = (int)(ARRAY_SIZE(generate_modules_list)) - 1;

    printf("\n");

    for (int i = 0; i < len; i++) {
        printf("  %d.%s\n", i + 1, generate_modules_list[i]->name);
        printf("    %s\n", i18n_tr(generate_modules_list[i]->short_desc
                                       ? generate_modules_list[i]->short_desc
                                       : generate_modules_list[i]->desc));
        printf("\n");
    }
}

void help_generate_module(Generator *module) {
    if (!module) {
        LOG(LEVEL_ERROR, "no specified generate module.\n");
        return;
    }

    printf("\n");
    printf("  %s%s\n", i18n_tr("GenerateModule Name: "), module->name);
    printf("\n");
    printf("  %s", i18n_tr("Description:\n"));
    xprint(i18n_tr(module->desc), 6, 80);
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
            xprint(i18n_tr(module->params[j].help_text), 6, 80);
            printf("\n\n");
        }
    }

    printf("\n");
}

bool generate_init_nothing(const XConf *xconf, uint64_t *count_targets,
                           uint64_t *count_endpoints, bool *init_ipv4,
                           bool *init_ipv6) {
    return true;
}

/*implemented `generate_modules_close`*/
void generate_close_nothing(const XConf *xconf) {}