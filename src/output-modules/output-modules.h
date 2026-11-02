#ifndef OUTPUT_MODULES_H
#define OUTPUT_MODULES_H

#include "output-types.h"
#include "../util-misc/configer.h"

struct XtateConf;

/**
 * Do init for outputing
 */
typedef bool (*output_modules_init)(const struct XtateConf *xconf,
                                    const OutConf          *out);

/**
 * Output one result
 */
typedef void (*output_modules_result)(OutItem *item);

/**
 * Do close for outputing
 */
typedef void (*output_modules_close)(const OutConf *out);

struct OutputModule {
    const char *name;
    const char *short_desc; /*an optional short description*/
    const char *desc;
    bool        need_file; /*need to specify an output file string*/
    ConfParam  *params;

    output_modules_init   init_cb;
    output_modules_result result_cb;
    output_modules_close  close_cb;
};

const char *output_level_to_string(OutLevel level);

/*prepare for outputing results*/
bool output_init(const struct XtateConf *xconf, OutConf *out);

/**
 * output a result within item and release datachain(report) in it.
 */
void output_result(const OutConf *out, OutItem *item);

/*destroy resources of output*/
void output_close(OutConf *out);

/**
 * Mark the output sink as failed after retries. The scan loop stops and exits
 * non-zero instead of silently losing more results.
 */
void output_mark_fatal(void);
bool output_has_fatal_error(void);

Output *get_output_module_by_name(const char *name);

/*list fuzzy matched modules*/
void list_searched_output_modules(const char *name);

void list_all_output_modules();

void help_output_module(Output *module);

/************************************************************************
Some useful implemented interfaces
************************************************************************/

bool output_init_nothing(const struct XtateConf *xconf, const OutConf *out);

void output_result_nothing(OutItem *item);

void output_close_nothing(const OutConf *out);

#endif
