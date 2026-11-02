/**
 * SCAN MODULES make you send and handle raw packet with
 * Xtate easily.
 *
 * NOTE: It's a multi-thread process internally.
 * Keep your modules thread-safe!
 */
#ifndef SCAN_MODULES
#define SCAN_MODULES

#include <stdlib.h>

#include "../util-misc/configer.h"
#include "../output-modules/output-types.h"
#include "../stack/stack-queue.h"
#include "../target/target.h"
#include "../target/target-ipaddress.h"
#include "../proto/proto-preprocess.h"
#include "../probe-modules/probe-types.h"
#include "scan-types.h"

struct XtateConf;
struct ProbeModule;

#define SM_DFT_DEDUP_TYPE 0

/***************************************************************************
 * * callback functions for Init
 ****************************************************************************/

/**
 * !Happens in Main Thread.
 * Do some initialization here if you have to.
 *
 * !Must be implemented.
 *
 * @param xconf main conf of xtate
 * @return false for initing failed and exit process.
 */
typedef bool (*scan_modules_init)(const struct XtateConf *xconf);

/***************************************************************************
 * * callback functions for Transmit
 ****************************************************************************/

/**
 * !Only step for transmitting. Happens in Tx Thread.
 * Do the first packet transmitting for every target.
 *
 * !Must be implemented.
 * !Must be thread safe for itself.
 *
 * @param entropy a rand seed (generated or user-specified).
 * @param target info of target.
 * @param px packet buffer to transmit. (Max Length is PKT_BUF_SIZE)
 * @param len length of packet data we filled.
 * @return true if need to transmit one more packet.
 */
typedef bool (*scan_modules_transmit)(uint64_t entropy, ScanTarget *target,
                                      unsigned char *px, size_t *len);

/***************************************************************************
 * * callback functions for Receive
 ****************************************************************************/

/**
 * !First Step for recving. Happens in Rx Thread.
 * Do following things for a received packet in orders:
 *  1. Record or drop.
 *  2. Is and How to dedup or drop.
 *
 * !Must be implemented.
 * !Must be thread safe for other funcs.
 *
 * @param entropy a rand seed (generated or user-specified).
 * @param recved info of received packet.
 * @param pre some preHandle decisions we have to make.
 */
typedef void (*scan_modules_validate)(uint64_t entropy, Recved *recved,
                                      PreHandle *pre);

/**
 * !Second Step for recving. Happens in Rx Handle Thread.
 * Do following things for a received packet:
 *  1. Is and How to output a result.
 *  2. How and What packet to response.
 *
 * !Must be implemented.
 * !Must be thread safe for itself.
 *
 * @param th_idx the index of receive handler thread.
 * @param entropy a rand seed (generated or user-specified).
 * @param valid_pkt info of validated packet.
 * @param item results we have to fill to output.
 * @param stack packet buffer queue stack for preparing transmitting by us.
 */
typedef void (*scan_modules_handle)(unsigned th_idx, uint64_t entropy,
                                    ValidPacket *valid_pkt, OutItem *item,
                                    NetStack *stack);

/***************************************************************************
 * * callback functions for Polling
 ****************************************************************************/

/**
 * !Happens in Rx Handle Thread.
 * Some internal status of ScanModules should be updated in real time.
 * This func would be called in every loop of packet handling just like
 * in real time.
 * NOTE: Don't block or waste time in this func.
 *
 * !Must be implemented.
 * !Must be thread safe for itself.
 *
 * @param th_idx the index of receive handler thread.
 */
typedef void (*scan_modules_poll)(unsigned th_idx);

/***************************************************************************
 * * callback functions for Close
 ****************************************************************************/

/**
 * !Happens in Main Thread.
 * It happens before normal exit in mainscan function.
 * And we could do some clean-ups.
 *
 * !Must be implemented.
 */
typedef void (*scan_modules_close)();

/***************************************************************************
 * * callback functions for additional Status Update
 ****************************************************************************/

/**
 * !Happens in Main Thread.
 * Some scan modules need to add additional info in status print.
 * This func allows it to return a C-string as additional status print.
 * NOTE: Don't block or waste time in this func.
 *
 * !Must be implemented.
 * !Must be thread safe for other funcs.
 *
 * @param status buf to set additional status data in max size of
 * SM_STATUS_SIZE. Do nothing if additonal status data.
 */
typedef void (*scan_modules_status)(char *status);

typedef struct ScanModule {
    const char     *name;
    /*set zero if not using probe*/
    const ProbeType required_probe_type;
    /*just for pcap to avoid copying uninteresting packets from the kernel to
     * user mode.*/
    const char     *bpf_filter;
    ConfParam      *params;
    struct ProbeModule *probe;
    const char     *short_desc; /*an optional short description*/
    const char     *desc;

    /*for init*/
    scan_modules_init     init_cb;
    /*for transmit*/
    scan_modules_transmit transmit_cb;
    /*for receive*/
    scan_modules_validate validate_cb;
    scan_modules_handle   handle_cb;
    /*for polling*/
    scan_modules_poll     poll_cb;
    /*for close*/
    scan_modules_close    close_cb;
    /*for status*/
    scan_modules_status   status_cb;
} Scanner;

struct ScanModule *get_scan_module_by_name(const char *name);

/*list fuzzy matched modules*/
void list_searched_scan_modules(const char *name);

void list_all_scan_modules();

void help_scan_module(Scanner *module);

/************************************************************************
Some useful implemented interfaces
************************************************************************/

/*implemented `scan_modules_init`*/
bool scan_init_nothing(const struct XtateConf *params);

/*implemented `scan_modules_poll`*/
void scan_poll_nothing(unsigned th_idx);

/*implemented `scan_modules_close`*/
void scan_close_nothing();

void scan_no_status(char *status);

#endif