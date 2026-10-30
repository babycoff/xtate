/**
 * Born and updated from masscan's tcp stack.
 *
 * Modified and Created by Alvin Chen 2024.
 */
#ifndef STACK_TCP_CORE_H
#define STACK_TCP_CORE_H

#include "stack-queue.h"
#include "../templ/templ-pkt.h"
#include "../target/target-ipaddress.h"
#include "../probe-modules/probe-modules.h"
#include "../output-modules/output-modules.h"

typedef enum TCP_What {
    TCP_WHAT_TIMEOUT, /*The connection time is expired*/
    TCP_WHAT_SYNACK,  /*Received SYN-ACK*/
    TCP_WHAT_RST,     /*Received RST*/
    TCP_WHAT_FIN,     /*Received FIN*/
    TCP_WHAT_ACK,     /*Received ACK (ignored data)*/
    TCP_WHAT_DATA,    /*Received DATA (just focus data)*/
} TcpWhat;

typedef enum App_State AppState;
typedef enum App_Event AppEvent;
typedef enum SOCK_Res  SockRes;

typedef struct TCP_StackHandler    TCP_Stack;
typedef struct TCP_Control_Block   TCB;
typedef struct TCP_ConnectionTable TCP_Table;

TCP_Table *tcpcon_create_table(size_t entry_count, NetStack *stack,
                               TmplPkt *tcp_template, TmplPkt *syn_template,
                               TmplPkt *rst_template, OutConf *out,
                               unsigned timeout, uint64_t entropy);

void tcpcon_destroy_table(TCP_Table *tcpcon);

/**
 * Handle timeout event  for now time.
 * Logically, we need wall time here.
 *
 * @param tcpcon tcp conn table
 * @param secs now time secs
 * @param usecs now time usecs
 */
void tcpcon_timeouts(TCP_Table *tcpcon, unsigned secs, unsigned usecs);

void stack_incoming_tcp(TCP_Table *tcpcon, TCB *entry, TcpWhat what,
                        const unsigned char *payload, size_t payload_length,
                        unsigned secs, unsigned usecs, unsigned seqno_them,
                        unsigned ackno_them);

TCB *tcpcon_lookup_tcb(TCP_Table *tcpcon, ipaddress ip_src, ipaddress ip_dst,
                       unsigned port_src, unsigned port_dst);

/**
 * Create a new TCB (TCP control block. It's created only in two places,
 * either because we've initiated an outbound TCP connection, or we've
 * received incoming SYN-ACK from a probe.
 * @param mss the mss of in synack. set it to 0 if non-mss then we use default
 * 1460
 */
TCB *tcpcon_create_tcb(TCP_Table *tcpcon, ipaddress ip_src, ipaddress ip_dst,
                       unsigned port_src, unsigned port_dst, unsigned my_seqno,
                       unsigned their_seqno, unsigned ttl, unsigned mss,
                       const Probe *probe, unsigned secs, unsigned usecs);

/**
 * get active tcb count
 */
uint64_t tcpcon_active_count(TCP_Table *tcpcon);

bool tcb_is_active(TCB *tcb);

SockRes tcpapi_set_timeout(TCP_Stack *socket, unsigned secs, unsigned usecs);

/**
 * Change from the "send" state to the "receive" state.
 * Has no effect if in any state other than "send".
 * This is none-blocking, an event will be triggered
 * later that has the data.
 */
SockRes tcpapi_recv(TCP_Stack *socket);

/**
 * just send data but not close
 */
SockRes tcpapi_send_data(TCP_Stack *socket, const void *buf, size_t length,
                         unsigned is_dynamic);

SockRes tcpapi_change_app_state(TCP_Stack *socket, AppState new_app_state);

/**
 * Send RST and del TCB to close the conn quickly.
 * Call this only when the upper-layer probe want to close it actively.
 */
SockRes tcpapi_close(TCP_Stack *socket);

/**
 * Media between Probe and our simplified TCP stack
 */
void application_event(TCP_Stack *socket, AppEvent cur_event,
                       const void *payload, size_t payload_length);

/* Regression test used by --selftest. */
int tcp_seg_ack_selftest(void);

#endif
