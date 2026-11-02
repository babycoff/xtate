#ifndef XTATUS_H
#define XTATUS_H

#include <stdint.h>

#define XTS_RATE_CACHE 8 /*must be power of 2*/
#define XTS_ADD_SIZE   96

typedef struct XtatusPrintItem {
    uint64_t cur_count;
    uint64_t max_count;
    uint64_t repeat_count;
    double   cur_pps;
    double   tx_queue_ratio;
    double   rx_queue_ratio;
    uint64_t total_successed;
    uint64_t total_failed;
    uint64_t total_info;
    uint64_t total_sent;
    uint64_t exiting_secs;
    char     add_status[XTS_ADD_SIZE];
    unsigned print_in_json : 1;
} XtatusItem;

typedef struct XtatusPrinter {
    /**
     * For smoothly calculate remaining secs.
     */
    struct {
        double   clock;
        uint64_t count;
    } last;
    double   last_rates[XTS_RATE_CACHE];
    unsigned last_count;
    /*statistics*/
    uint64_t total_successed;
    uint64_t total_sent;
    /*switches*/
    unsigned no_ansi        : 1;
    unsigned is_infinite    : 1;
    unsigned print_queue    : 1;
    unsigned print_info_num : 1;
    unsigned print_hit_rate : 1;
} Xtatus;

void xtatus_print(Xtatus *xtatus, XtatusItem *item);

void xtatus_finish(Xtatus *xtatus);

/**
 * Set Xtatus to zero and init some fields.
 */
void xtatus_start(Xtatus *xtatus);

#endif
