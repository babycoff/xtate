#ifndef OUTPUT_MODULES_H
#define OUTPUT_MODULES_H

#include <time.h>
#include <inttypes.h>

#include "../target/target.h"
#include "../as/as-query.h"
#include "../util-data/data-chain.h"
#include "../util-misc/configer.h"

#define OUT_RSN_SIZE 30
#define OUT_CLS_SIZE 30

struct XtateConf;

typedef struct OutputModule Output;
typedef struct OutputConfig OutConf;

typedef enum OutputLevel {
    OUT_INFO    = 0,
    OUT_FAILURE = 1,
    OUT_SUCCESS = 2,
} OutLevel;

/**
 * modifiable to change target.
 */
typedef struct OutputItem {
    /**This timestamp can be set in diff meanings by yourself like time of
     * receiving packet or time of result generated. It will be set in output
     * func by global time if hasn't be set by any module.*/
    time_t    timestamp;
    /**Type of result item itself. INFO and FAILURE are not to be output by
     * default unless using `--show fail` or `--show info`.*/
    OutLevel  level;
    /**
     * Info of target */
    Target    target;
    /**Type of this result. It is recommended to set a value.
     * No double or single quotes in it for output format.
     * It won't be outputting in stdout and text if start with zero, suggest to
     * set it*/
    char      classification[OUT_CLS_SIZE];
    /**Why we set this result to that classification.
     * No double or single quotes in it for output format.
     * It won't be outputting in stdout and text if start with zero, suggest to
     * set it*/
    char      reason[OUT_RSN_SIZE];
    /**Other thing need to be report. It's a dynamic and user-defined field in
     * key-value format.*/
    DataChain scan_report;   /*report from scan module*/
    DataChain probe_report;  /*report from probe module*/
    DataChain output_report; /*report from output module*/
    /**This result item won't be output if it set to true*/
    unsigned  no_output : 1;
    /**Port info won't be output if it set to true*/
    unsigned  no_port   : 1;
} OutItem;

struct OutputConfig {
    Output          *output_module;
    char            *output_args;
    char             output_filename[256];
    uint64_t         total_successed;
    uint64_t         total_failed;
    uint64_t         total_info;
    void            *module_mutex;
    void            *stdout_mutex;
    struct AS_Query *as_query;
    unsigned         output_as_info  : 1;
    unsigned         is_append       : 1;
    unsigned         is_out_screen   : 1;
    unsigned         is_show_failed  : 1;
    unsigned         is_show_info    : 1;
    unsigned         no_show_success : 1;
};

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