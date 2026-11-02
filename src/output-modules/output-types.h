#ifndef OUTPUT_TYPES_H
#define OUTPUT_TYPES_H

/*
 * Result/output types shared by scan, probe, stack and output code.
 *
 * Keep module-registry callbacks and output implementation declarations in
 * output-modules.h; most consumers only need these types.
 */

#include <inttypes.h>
#include <stdint.h>
#include <time.h>

#include "../target/target.h"
#include "../util-data/data-chain.h"

#define OUT_RSN_SIZE 30
#define OUT_CLS_SIZE 30

struct AS_Query;

typedef struct OutputModule Output;
typedef struct OutputConfig OutConf;

typedef enum OutputLevel {
    OUT_INFO    = 0,
    OUT_FAILURE = 1,
    OUT_SUCCESS = 2,
} OutLevel;

/**
 * Result item produced by a ScanModule or ProbeModule.
 */
typedef struct OutputItem {
    /**Timestamp can be set by the producer; the output layer fills it if zero.*/
    time_t    timestamp;
    /**INFO and FAILURE are not shown by default.*/
    OutLevel  level;
    Target    target;
    char      classification[OUT_CLS_SIZE];
    char      reason[OUT_RSN_SIZE];
    DataChain scan_report;
    DataChain probe_report;
    DataChain output_report;
    unsigned  no_output : 1;
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

#endif
