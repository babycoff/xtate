#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#include <stdlib.h>

#include "../target/target.h"
#include "../util-misc/configer.h"
#include "../proto/proto-datapass.h"
#include "../output-modules/output-types.h"
#include "probe-types.h"

struct XtateConf;

/**
 * FIXME: It should be a value a little less than PKT_BUF_SIZE,
 * but I'm lazy to estimate the actual number.
 */
#define PM_PAYLOAD_SIZE 2048

/***************************************************************************
 * * callback functions for Init
 ****************************************************************************/

/**
 * !Must be implemented.
 *
 * @param xconf main conf of xtate
 * @return FALSE to exit process if init failed
 */
typedef bool (*probe_modules_init)(const struct XtateConf *xconf);

/***************************************************************************
 * * callback functions for probe(hello) payload making in Non-STATE type
 ****************************************************************************/

/**
 * not modifiable in probe module internal, we can't change the actual target.
 */
typedef struct ProbeModuleTarget {
    Target   target;
    unsigned cookie; /*for cookie setting of UDP type probe*/
    unsigned index;  /*for identifying of multi probes per target*/
} ProbeTarget;

/**
 * !Happens in Tx Thread or Rx Handle Thread for different ScanModules.
 *
 * Make hello payload data for a target.
 * We could embed a cookie to payload for response validating in ProbeType_UDP
 * mode.
 *
 *
 * !Must be implemented.
 * !Must be thread safe for itself.
 *
 * @param target info of target
 * @param payload_buf buffer to fill with payload. (Length is PM_PAYLOAD_SIZE)
 * @return paylaod length.
 */
typedef size_t (*probe_modules_make_payload)(ProbeTarget   *target,
                                             unsigned char *payload_buf);

/**
 * !Happens in Tx Thread or Rx Thread for different ScanModules.
 * This func would be called even if xtate won't send the payload.
 *
 * !Must be implemented for ProbeType_TCP.
 * !Must check index range in probe slot
 * !Must be thread safe for itself.
 *
 * @param target info of target
 * @return length of payload data
 */
typedef size_t (*probe_modules_get_payload_length)(ProbeTarget *target);

/***************************************************************************
 * * callback functions for response processing in Non-STATE type
 ****************************************************************************/

/**
 * !Happens in Rx Thread
 *
 * Validate whether the response is for us(because of stateless udp).
 * This is useful when ScanModule cannot validate perfectly in protocol level.
 * But UdpScanner uses target range containing as default pre-validation. This
 * is enough for most cases.
 *
 * !Must be implemented for ProbeType_UDP.
 * !Must be thread safe for other funcs.
 *
 * @param target info of target
 * @param px response data, it can be zero
 * @param sizeof_px len of reponse
 * @return TRUE if the response is for us.
 */
typedef bool (*probe_modules_validate_response)(ProbeTarget         *target,
                                                const unsigned char *px,
                                                unsigned             sizeof_px);

/**
 * !Happens in Rx Handle Thread,
 * Decide the results for the response
 *
 * !Must be implemented in Non-STATE type.
 * !Must be thread safe for other funcs.
 *
 * @param th_idx the index of receive handler thread.
 * @param target info of target
 * @param px response data
 * @param sizeof_px len of reponse, must>0
 * @param item to define output content.
 * @return currently reserved; multi-slot triggering is owned by ProbeSlotPlan.
 */
typedef unsigned (*probe_modules_handle_response)(unsigned             th_idx,
                                                  ProbeTarget         *target,
                                                  const unsigned char *px,
                                                  unsigned sizeof_px,
                                                  OutItem *item);

/***************************************************************************
 * * callback functions for ProbeType_STATE only
 ****************************************************************************/

typedef struct StateOfProbe {
    /*impossible to exceed the state limitation*/
    unsigned state;
    /*defined by probe itself in need*/
    void    *data;
} ProbeState;

/**
 * !Happens in Rx Handle Thread,
 * !Same (ip_them, port_them, ip_me, port_me) in same Thread
 * Do init for a connection
 *
 * !Must be implemented for Probe_TYPE STATE
 * !Must be thread safe for itself.
 *
 * @param state  probe state
 * @param target target info
 * @return true if conn init success. conn will be terminated if returned
 * false.
 */
typedef bool (*probe_modules_conn_init)(ProbeState *state, ProbeTarget *target);

/**
 * !Happens in Rx Handle Thread,
 * !Same (ip_them, port_them, ip_me, port_me) in same Thread
 * Make correspond hello payload data for a target.
 *
 * !Must be implemented for Probe_TYPE STATE
 * !Must be thread safe for itself.
 *
 * @param state probe state
 * @param target info of a target
 * @param payload_buf buffer to fill with payload. (Length is PM_PAYLOAD_SIZE)
 * @return paylaod length.
 */
typedef void (*probe_modules_make_hello)(DataPass *pass, ProbeState *state,
                                         ProbeTarget *target);

/**
 *
 * !Happens in Rx Handle Thread
 * !Same (ip_them, port_them, ip_me, port_me) in same Thread
 * Interacting with target after receive data.
 *
 * !Must be implemented for ProbeType_STATE.
 * !Must be thread safe for itself.
 *
 * @param pass   used for pass data(for sending) to down-layer protocol.
 * @param state  state that probe setted.
 * @param out    used for outputing results.
 * @param target info of a target
 * @param px response data
 * @param sizeof_px len of reponse
 * @return currently reserved; multi-slot triggering is owned by ProbeSlotPlan.
 */
typedef unsigned (*probe_modules_parse_response)(
    DataPass *pass, ProbeState *state, OutConf *out, ProbeTarget *target,
    const unsigned char *px, unsigned sizeof_px);

/**
 * !Happens in Rx Handle Thread,
 * !Same (ip_them, port_them, ip_me, port_me) in same Thread
 * Do init for a connection
 *
 * !Must be implemented for Probe_TYPE STATE
 * !Must be thread safe for itself.
 *
 * @param state probe state
 * @param target target info
 */
typedef void (*probe_modules_conn_close)(ProbeState  *state,
                                         ProbeTarget *target);

/***************************************************************************
 * * callback functions for Close
 ****************************************************************************/

/**
 * It happens before normal exit in mainscan function.
 * !Must be implemented.
 */
typedef void (*probe_modules_close)();

typedef enum ProbeSlotTrigger {
    ProbeSlot_None = 0,
    /* Send every slot from the first scan iteration. */
    ProbeSlot_Always = 1,
    /* Send remaining slots only after the first slot gets a reply that the
     * probe accepts.  JARM uses this for its ten TLS ClientHello variants. */
    ProbeSlot_AfterFirstReply = 2,
} ProbeSlotTrigger;

typedef bool (*probe_slots_continue)(ProbeTarget         *target,
                                     const unsigned char *px,
                                     unsigned             sizeof_px);

typedef struct ProbeSlotPlan {
    unsigned           count; /* 0 or 1 means a single flow; 10 for JARM */
    ProbeSlotTrigger   trigger;
    probe_slots_continue continue_cb; /* optional, for AfterFirstReply */
} ProbeSlotPlan;

typedef struct ProbeModule {
    const char     *name;
    const ProbeType type;
    const ProbeSlotPlan slots;
    /*just for statefull scan*/
    unsigned        hello_wait;
    const char     *short_desc; /*an optional short description*/
    const char     *desc;
    ConfParam      *params;

    /*for init*/
    probe_modules_init               init_cb;
    /*for stateless payload*/
    probe_modules_make_payload       make_payload_cb;
    /*for stateless validate (tcp)*/
    probe_modules_get_payload_length get_payload_length_cb;
    /*for stateless validate (udp)*/
    probe_modules_validate_response  validate_response_cb;
    /*for stateless response*/
    probe_modules_handle_response    handle_response_cb;
    /*for stateful process*/
    probe_modules_conn_init          conn_init_cb;
    probe_modules_make_hello         make_hello_cb;
    probe_modules_parse_response     parse_response_cb;
    probe_modules_conn_close         conn_close_cb;
    /*for close*/
    probe_modules_close              close_cb;
} Probe;

static inline unsigned probe_slot_count(const Probe *probe) {
    return (probe && probe->slots.count > 1) ? probe->slots.count : 1;
}

Probe *get_probe_module_by_name(const char *name);

const char *get_probe_type_name(const ProbeType type);

int probe_type_to_string(unsigned type, char *string, size_t str_len);

/*list fuzzy matched modules*/
void list_searched_probe_modules(const char *name);

void list_all_probe_modules();

void help_probe_module(Probe *module);

/************************************************************************
Some useful implemented interfaces
************************************************************************/

/*implemented `probe_modules_init`*/
bool probe_init_nothing(const struct XtateConf *xconf);

size_t probe_make_no_payload(ProbeTarget *target, unsigned char *payload_buf);

/*implemented `probe_modules_get_payload_length`*/
size_t probe_no_payload_length(ProbeTarget *target);

/*implemented `probe_modules_handle_reponse`*/
unsigned probe_report_nothing(unsigned th_idx, ProbeTarget *target,
                              const unsigned char *px, unsigned sizeof_px,
                              OutItem *item);

/*implemented `probe_modules_handle_reponse`*/
unsigned probe_just_report_banner(unsigned th_idx, ProbeTarget *target,
                                  const unsigned char *px, unsigned sizeof_px,
                                  OutItem *item);

/*implemented `probe_modules_close`*/
void probe_close_nothing();

bool probe_conn_init_nothing(ProbeState *state, ProbeTarget *target);

void probe_conn_close_nothing(ProbeState *state, ProbeTarget *target);

bool probe_all_response_valid(ProbeTarget *target, const unsigned char *px,
                              unsigned sizeof_px);

#ifndef NOT_FOUND_OPENSSL
int tlsstate_scratch_selftest(void);
#endif

#endif