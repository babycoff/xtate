/*
 * This is the core TCP layer in the stack. It's notified of incoming
 * IP datagrams containing TCP protocols. This is where the TCP state
 * diagram is handled.
 *
 *
 *                              +---------+ ---------\      active OPEN
 *                              |  CLOSED |            \    -----------
 *                              +---------+<---------\   \   create TCB
 *                                |     ^              \   \  snd SYN
 *                   passive OPEN |     |   CLOSE        \   \
 *                   ------------ |     | ----------       \   \
 *                    create TCB  |     | delete TCB         \   \
 *                                V     |                      \   \
 *                              +---------+            CLOSE    |    \
 *                              |  LISTEN |          ---------- |     |
 *                              +---------+          delete TCB |     |
 *                   rcv SYN      |     |     SEND              |     |
 *                  -----------   |     |    -------            |     V
 * +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 * |         |<-----------------           ------------------>|         |
 * |   SYN   |                    rcv SYN                     |   SYN   |
 * |   RCVD  |<-----------------------------------------------|   SENT  |
 * |         |                    snd ACK                     |         |
 * |         |------------------           -------------------|         |
 * +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
 *   |           --------------   |     |   -----------
 *   |                  x         |     |     snd ACK
 *   |                            V     V
 *   |  CLOSE                   +---------+
 *   | -------                  |  ESTAB  |
 *   | snd FIN                  +---------+
 *   |                   CLOSE    |     |    rcv FIN
 *   V                  -------   |     |    -------
 * +---------+          snd FIN  /       \   snd ACK          +---------+
 * |  FIN    |<-----------------           ------------------>|  CLOSE  |
 * | WAIT-1  |------------------                              |   WAIT  |
 * +---------+          rcv FIN  \                            +---------+
 *   | rcv ACK of FIN   -------   |                            CLOSE  |
 *   | --------------   snd ACK   |                           ------- |
 *   V        x                   V                           snd FIN V
 * +---------+                  +---------+                   +---------+
 * |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 * +---------+                  +---------+                   +---------+
 *   |                rcv ACK of FIN |                 rcv ACK of FIN |
 *   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
 *   |  -------              x       V    ------------        x       V
 *    \ snd ACK                 +---------+delete TCB         +---------+
 *     ------------------------>|TIME WAIT|------------------>| CLOSED  |
 *                              +---------+                   +---------+
 *
 */

/**
 * !BUT
 * For code clean, fast scanning and papers...Yeah, I improve(or downgrade)
 * the TCP stack(FSM) to a more simpler one with just 2 states( with a init
 * state). Actually, it combines stateless and stateful mode, also I call it
 * hybrid-state lightweight TCP stack----HLTCP.
 *
 * Born and updated from masscan's tcp stack.
 *
 * Modified and Created by Alvin Chen 2024.
 */
#include "stack-tcp-core.h"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdarg.h>

#include "stack-queue.h"
#include "stack-src.h"

#include "../globals.h"
#include "../templ/templ-tcp.h"
#include "../target/target-cookie.h"
#include "../timeout/event-timeout.h"
#include "../util-misc/misc.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"

#ifdef _MSC_VER
#pragma warning(disable : 4204)
#define snprintf _snprintf
#pragma warning(disable : 4996)
#endif

#define TCP_CORE_DEFAULT_EXPIRE 30 /* half a minute before destroying tcb */
#define TCP_CORE_DEFAULT_MSS    1460
#define TCP_CORE_RTO_SECS       1

static bool _is_tcp_debug = false;

typedef enum TCP_State {
    STATE_SYNSENT = 0, /* init state, must be zero */
    STATE_SENDING,     /* sending now */
    STATE_RECVING,     /* want to receive */
} TcpState;

/**
 * Abstract TCP data exchange to uppper application service State and Event to
 * fit our design and interfaces.
 */
enum App_State {
    APP_STATE_INIT = 0,   /*init state, must be zero*/
    APP_STATE_RECV_HELLO, /*waiting for hello response*/
    APP_STATE_RECVING,    /*waiting for payload*/
    APP_STATE_SEND_FIRST, /*our turn to say hello*/
    APP_STATE_SENDING,    /*data sending doesn't finish*/
};

enum App_Event {
    APP_WHAT_CONNECTED,    /*conn has been established*/
    APP_WHAT_RECV_TIMEOUT, /*for hello waiting*/
    APP_WHAT_RECV_PAYLOAD, /*payload received*/
    APP_WHAT_SENDING,      /*there's data is sending now*/
    APP_WHAT_SEND_SENT,    /*data has been sent and acked*/
};

typedef struct TCP_Segment {
    struct TCP_Segment *next;
    unsigned char      *buf;
    size_t              length;
    unsigned            seqno;
    unsigned            is_dynamic : 1;
} TcpSegment;

struct TCP_Control_Block {
    ipaddress ip_me;
    ipaddress ip_them;
    uint16_t  port_me;
    uint16_t  port_them;
    union {
        uint32_t seqno_me; /* next seqno I will use for transmit */
        uint32_t ackno_them;
    };
    union {
        uint32_t seqno_them; /* the next seqno I expect to receive */
        uint32_t ackno_me;
    };

    /*conn's initial seqno for debugging */
    uint32_t seqno_me_first;
    uint32_t seqno_them_first;

    TcpSegment *segments;
    TcpState    tcpstate;
    AppState    app_state;
    uint8_t     ttl;
    uint8_t     syns_sent; /* reconnect */
    uint16_t    mss;       /* maximum segment size 1460 */
    time_t      when_created;
    unsigned    is_active : 1; /*in-use/allocated or to be del soon*/

    const Probe *probe;
    ProbeState   probe_state;

    TmEntry timeout[1]; /*only one for this TCB*/
    TCB    *next;
};

struct TCP_ConnectionTable {
    TCB **entries;
    TCB  *freed_list;

    TmplPkt  *tcp_template;
    TmplPkt  *syn_template;
    TmplPkt  *rst_template;
    Timeouts *timeouts;
    NetStack *stack;
    OutConf  *out_conf;

    unsigned count;
    unsigned mask;

    uint16_t src_port_start;
    uint16_t mss_me;
    unsigned expire;

    uint64_t active_count;
    uint64_t entropy;
};

struct TCP_StackHandler {
    TCP_Table *tcpcon;
    TCB       *tcb;
    unsigned   secs;
    unsigned   usecs;
};

enum SOCK_Res {
    SOCKERR_NONE = 0, /* no error */
    SOCKERR_EBADF,    /* bad socket descriptor */
};

enum DestroyReason {
    Reason_Timeout,  /*close because of timeout*/
    Reason_FIN,      /*close because of FIN*/
    Reason_RST,      /*close because of RST*/
    Reason_Close,    /*close it actively*/
    Reason_Anomaly,  /*close because of anomaly*/
    Reason_Shutdown, /*cleaning TCP connection*/
};

uint64_t tcpcon_active_count(TCP_Table *tcpcon) { return tcpcon->active_count; }

bool tcb_is_active(TCB *tcb) { return tcb->is_active == 1; }

/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *_tcp_state_to_string(TcpState state) {
    switch (state) {
        case STATE_SYNSENT:
            return "SYN_SENT";
        case STATE_SENDING:
            return "SENDING";
        case STATE_RECVING:
            return "RECVING";

        default:
            return "UNKN_STATE";
    }
}

/***************************************************************************
 ***************************************************************************/
static void _vLOGtcb(const TCB *tcb, int dir, const char *fmt, va_list marker) {
    char                  sz[256];
    ipaddress_formatted_t fmt1 = ipaddress_fmt(tcb->ip_them);

    if (tcb->ip_them.ipv4 == 4) {
        snprintf(sz, sizeof(sz), "(%s:%u %4u,%4u) %s:%5u (%4u,%4u) {%s} ",
                 fmt1.string, tcb->port_them,
                 tcb->seqno_them - tcb->seqno_them_first,
                 tcb->ackno_me - tcb->seqno_them_first,
                 (dir > 0) ? "-->" : "<--", tcb->port_me,
                 tcb->seqno_me - tcb->seqno_me_first,
                 tcb->ackno_them - tcb->seqno_me_first,
                 _tcp_state_to_string(tcb->tcpstate));
    } else {
        snprintf(sz, sizeof(sz), "([%s]:%u %4u,%4u) %s:%5u (%4u,%4u) {%s} ",
                 fmt1.string, tcb->port_them,
                 tcb->seqno_them - tcb->seqno_them_first,
                 tcb->ackno_me - tcb->seqno_them_first,
                 (dir > 0) ? "-->" : "<--", tcb->port_me,
                 tcb->seqno_me - tcb->seqno_me_first,
                 tcb->ackno_them - tcb->seqno_me_first,
                 _tcp_state_to_string(tcb->tcpstate));
    }
    sz[255] = '\0';
    if (dir == 2) {
        char *brace = strchr(sz, '{');
        memset(sz, ' ', brace - sz);
    }
    fprintf(stderr, "[TCB] %s", sz);
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}

/***************************************************************************
 ***************************************************************************/
static void _LOGtcb(const TCB *tcb, int dir, const char *fmt, ...) {
    va_list marker;

    if (!_is_tcp_debug)
        return;
    va_start(marker, fmt);
    _vLOGtcb(tcb, dir, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 * Process all events, up to the current time, that need timing out.
 ***************************************************************************/
void tcpcon_timeouts(TCP_Table *tcpcon, unsigned secs, unsigned usecs) {
    TCB *tcb;

    uint64_t timestamp = TICKS_FROM_TV(secs, usecs);

    for (;;) {
        tcb = (TCB *)timeouts_remove(tcpcon->timeouts, timestamp);

        if (tcb == NULL)
            break;

        stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_TIMEOUT, 0, 0, secs, usecs,
                           tcb->seqno_them, tcb->ackno_them);

        /**
         * If the TCB hasn't been destroyed, then we need to make sure there is
         * always a timeout associated with it.
         * This is important for conn maintenance like:
         *     resending packets,
         *     deleting expired conns,
         *     etc.
         * */
        if (tcb->is_active && timeout_is_unlinked(tcb->timeout)) {
            timeouts_add(tcpcon->timeouts, tcb->timeout, offsetof(TCB, timeout),
                         TICKS_FROM_TV(secs + TCP_CORE_RTO_SECS, usecs));
        }
    }
}

/***************************************************************************
 ***************************************************************************/
TCP_Table *tcpcon_create_table(size_t entry_count, NetStack *stack,
                               TmplPkt *tcp_template, TmplPkt *syn_template,
                               TmplPkt *rst_template, OutConf *out,
                               unsigned expire, uint64_t entropy) {
    TCP_Table *tcpcon = CALLOC(1, sizeof(*tcpcon));

    /* Find nearest power of 2 to the tcb count, but don't go
     * over the number 16-million */
    {
        size_t new_entry_count;
        new_entry_count = 1;
        while (new_entry_count < entry_count) {
            new_entry_count *= 2;
            if (new_entry_count == 0) {
                new_entry_count = (1 << 24);
                break;
            }
        }
        if (new_entry_count > (1 << 24))
            new_entry_count = (1 << 24);
        if (new_entry_count < (1 << 10))
            new_entry_count = (1 << 10);
        entry_count = new_entry_count;
    }

    /* Create the table. */
    tcpcon->entries = MALLOC(entry_count * sizeof(TCB *));
    memset(tcpcon->entries, 0, entry_count * sizeof(TCB *));

    tcpcon->expire = expire;
    if (tcpcon->expire == 0)
        tcpcon->expire = TCP_CORE_DEFAULT_EXPIRE;

    bool is_found;
    tcpcon->mss_me = tcp_get_mss(syn_template->ipv4.packet,
                                 syn_template->ipv4.length, &is_found);
    if (!is_found)
        tcpcon->mss_me = TCP_CORE_DEFAULT_MSS;

    tcpcon->tcp_template   = tcp_template;
    tcpcon->syn_template   = syn_template;
    tcpcon->rst_template   = rst_template;
    tcpcon->entropy        = entropy;
    tcpcon->count          = (unsigned)entry_count;
    tcpcon->mask           = (unsigned)(entry_count - 1);
    tcpcon->timeouts       = timeouts_create(TICKS_FROM_SECS(time(0)));
    tcpcon->stack          = stack;
    tcpcon->out_conf       = out;
    tcpcon->src_port_start = stack->src->port.first;

    return tcpcon;
}

/***************************************************************************
 ***************************************************************************/
static int _TCB_EQUALS(const TCB *lhs, const TCB *rhs) {
    if (lhs->port_me != rhs->port_me || lhs->port_them != rhs->port_them)
        return 0;
    if (lhs->ip_me.version != rhs->ip_me.version)
        return 0;
    if (lhs->ip_me.version == 6) {
        if (memcmp(&lhs->ip_me.ipv6, &rhs->ip_me.ipv6,
                   sizeof(rhs->ip_me.ipv6)) != 0)
            return 0;
        if (memcmp(&lhs->ip_them.ipv6, &rhs->ip_them.ipv6,
                   sizeof(rhs->ip_them.ipv6)) != 0)
            return 0;
    } else {
        if (lhs->ip_me.ipv4 != rhs->ip_me.ipv4)
            return 0;
        if (lhs->ip_them.ipv4 != rhs->ip_them.ipv4)
            return 0;
    }

    return 1;
}

/***************************************************************************
 ***************************************************************************/
static void _tcb_change_state_to(TCB *tcb, TcpState new_state) {
    _LOGtcb(tcb, 2, "to {%s}\n", _tcp_state_to_string(new_state));
    tcb->tcpstate = new_state;
}

/***************************************************************************
 ***************************************************************************/
static unsigned _tcb_hash(ipaddress ip_me, unsigned port_me, ipaddress ip_them,
                          unsigned port_them, uint64_t entropy) {
    unsigned index;

    /* TCB hash table uses symmetric hash, so incoming/outgoing packets
     * get the same hash. */
    if (ip_me.version == 6) {
        ipv6address ipv6 = ip_me.ipv6;
        ipv6.hi ^= ip_them.ipv6.hi;
        ipv6.lo ^= ip_them.ipv6.lo;
        index = (unsigned)get_cookie_ipv6(ipv6, port_me ^ port_them, ipv6,
                                          port_me ^ port_them, entropy);
    } else {
        index = (unsigned)get_cookie_ipv4(
            ip_me.ipv4 ^ ip_them.ipv4, port_me ^ port_them,
            ip_me.ipv4 ^ ip_them.ipv4, port_me ^ port_them, entropy);
    }
    return index;
}

/***************************************************************************
 * Destroy a TCP connection entry. We have to unlink both from the
 * TCB-table as well as the timeout-table.
 ***************************************************************************/
static void _tcpcon_destroy_tcb(TCP_Table *tcpcon, TCB *tcb,
                                enum DestroyReason reason) {
    unsigned index;
    TCB    **one_entry;

    UNUSEDPARM(reason);

    index = _tcb_hash(tcb->ip_me, tcb->port_me, tcb->ip_them, tcb->port_them,
                      tcpcon->entropy);

    one_entry = &tcpcon->entries[index & tcpcon->mask];
    while (*one_entry && *one_entry != tcb)
        one_entry = &(*one_entry)->next;

    if (*one_entry == NULL) {
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(tcb->ip_them);
        LOG(LEVEL_WARN,
            "tcp.tcb: (%s %u) double freed, tcp state: %s.                     "
            " \n",
            ip_them_fmt.string, tcb->port_them,
            _tcp_state_to_string(tcb->tcpstate));
        return;
    }

    _LOGtcb(tcb, 2, "--DESTROYED--\n");

    /**
     * clean segments
     */
    while (tcb->segments) {
        TcpSegment *seg = tcb->segments;
        tcb->segments   = seg->next;

        if (seg->is_dynamic) {
            FREE(seg->buf);
        }

        FREE(seg);
    }

    /*do connection close for probe*/
    ProbeTarget target = {
        .target.ip_proto  = IP_PROTO_TCP,
        .target.ip_them   = tcb->ip_them,
        .target.port_them = tcb->port_them,
        .target.ip_me     = tcb->ip_me,
        .target.port_me   = tcb->port_me,
        .cookie           = 0, /*Probe_TYPE State doesn't need cookie*/
        .index            = tcb->port_me - tcpcon->src_port_start,
    };
    tcb->probe->conn_close_cb(&tcb->probe_state, &target);

    /*
     * Unlink this from the timeout system.
     */
    timeout_unlink(tcb->timeout);

    tcb->ip_them.ipv4 = (unsigned)~0;
    tcb->port_them    = (unsigned short)~0;
    tcb->ip_me.ipv4   = (unsigned)~0;
    tcb->port_me      = (unsigned short)~0;

    (*one_entry)       = tcb->next;
    tcb->next          = tcpcon->freed_list;
    tcpcon->freed_list = tcb;

    tcb->is_active = 0;
    tcpcon->active_count--;
}

/***************************************************************************
 ***************************************************************************/
void tcpcon_destroy_table(TCP_Table *tcpcon) {
    unsigned i;

    if (tcpcon == NULL)
        return;

    for (i = 0; i <= tcpcon->mask; i++) {
        while (tcpcon->entries[i]) {
            _tcpcon_destroy_tcb(tcpcon, tcpcon->entries[i], Reason_Shutdown);
        }
    }

    while (tcpcon->freed_list) {
        TCB *tcb           = tcpcon->freed_list;
        tcpcon->freed_list = tcb->next;
        FREE(tcb);
    }

    FREE(tcpcon->entries);
    FREE(tcpcon->timeouts);
    FREE(tcpcon);
}

/***************************************************************************
 * Called when we receive a "SYN-ACK" packet with the correct SYN-cookie.
 ***************************************************************************/
TCB *tcpcon_create_tcb(TCP_Table *tcpcon, ipaddress ip_me, ipaddress ip_them,
                       unsigned port_me, unsigned port_them, unsigned seqno_me,
                       unsigned seqno_them, unsigned ttl, unsigned mss,
                       const Probe *probe, unsigned secs, unsigned usecs) {
    unsigned index;
    TCB      tmp;
    TCB     *tcb;

    assert(ip_me.version != 0 && ip_them.version != 0);

    tmp.ip_me     = ip_me;
    tmp.ip_them   = ip_them;
    tmp.port_me   = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = _tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);
    tcb   = tcpcon->entries[index & tcpcon->mask];

    while (tcb && !_TCB_EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }

    if (tcb != NULL) {
        /* If it already exists, just return the existing one */
        return tcb;
    }

    /* Allocate a new TCB, using a pool */
    if (tcpcon->freed_list) {
        tcb                = tcpcon->freed_list;
        tcpcon->freed_list = tcb->next;
    } else {
        tcb = MALLOC(sizeof(TCB));
    }
    memset(tcb, 0, sizeof(TCB));

    tcb->next = tcpcon->entries[index & tcpcon->mask];
    tcpcon->entries[index & tcpcon->mask] = tcb;

    /*negotiate mss*/
    if (mss == 0 || mss > tcpcon->mss_me)
        tcb->mss = tcpcon->mss_me;
    else
        tcb->mss = mss;

    tcb->ip_me            = ip_me;
    tcb->ip_them          = ip_them;
    tcb->port_me          = (uint16_t)port_me;
    tcb->port_them        = (uint16_t)port_them;
    tcb->seqno_me         = seqno_me;
    tcb->seqno_them       = seqno_them;
    tcb->seqno_me_first   = seqno_me;
    tcb->seqno_them_first = seqno_them;
    tcb->when_created     = global_get_time();
    tcb->ttl              = (unsigned char)ttl;
    tcb->probe            = probe;

    /* Insert the TCB into the timeout. A TCB must always have a timeout
     * active to insure to be deleted. */
    timeout_init(tcb->timeout);
    timeouts_add(tcpcon->timeouts, tcb->timeout, offsetof(TCB, timeout),
                 TICKS_FROM_TV(secs + 1, usecs));

    /* The TCB is now allocated/in-use */
    assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);

    tcb->is_active = 1;
    tcpcon->active_count++;

    return tcb;
}

/***************************************************************************
 ***************************************************************************/
TCB *tcpcon_lookup_tcb(TCP_Table *tcpcon, ipaddress ip_me, ipaddress ip_them,
                       unsigned port_me, unsigned port_them) {
    unsigned index;
    TCB      tmp;
    TCB     *tcb;

    tmp.ip_me     = ip_me;
    tmp.ip_them   = ip_them;
    tmp.port_me   = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = _tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);
    tcb   = tcpcon->entries[index & tcpcon->mask];

    while (tcb && !_TCB_EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }

    return tcb;
}

/***************************************************************************
 ***************************************************************************/
static void _tcpcon_send_packet(TCP_Table *tcpcon, TCB *tcb, unsigned tcp_flags,
                                const unsigned char *payload,
                                size_t               payload_length) {
    PktBuf *response = 0;
    bool    is_syn   = (tcp_flags == TCP_FLAG_SYN);

    assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);

    /* If sending an ACK, print a message */
    if ((tcp_flags & TCP_FLAG_ACK) == TCP_FLAG_ACK) {
        _LOGtcb(tcb, 0, "xmit ACK ackingthem=%u\n",
                tcb->seqno_them - tcb->seqno_them_first);
    }

    response = stack_get_pktbuf(tcpcon->stack);

    /*use different template according to flags*/
    if (is_syn) {
        response->length = tcp_create_by_template(
            tcpcon->syn_template, tcb->ip_them, tcb->port_them, tcb->ip_me,
            tcb->port_me, tcb->seqno_me - 1, tcb->seqno_them, /*NOTE the seqno*/
            tcp_flags, 0, 0, payload, payload_length, response->px,
            sizeof(response->px));
    } else if (tcp_flags & TCP_FLAG_RST) {
        response->length = tcp_create_by_template(
            tcpcon->rst_template, tcb->ip_them, tcb->port_them, tcb->ip_me,
            tcb->port_me, tcb->seqno_me, tcb->seqno_them, tcp_flags, 0, 0,
            payload, payload_length, response->px, sizeof(response->px));
    } else {
        response->length = tcp_create_by_template(
            tcpcon->tcp_template, tcb->ip_them, tcb->port_them, tcb->ip_me,
            tcb->port_me, tcb->seqno_me, tcb->seqno_them, tcp_flags, 0, 0,
            payload, payload_length, response->px, sizeof(response->px));
    }

    stack_transmit_pktbuf(tcpcon->stack, response);
}

/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *_what_to_string(TcpWhat state) {
    switch (state) {
        case TCP_WHAT_TIMEOUT:
            return "TIMEOUT";
        case TCP_WHAT_SYNACK:
            return "SYNACK";
        case TCP_WHAT_RST:
            return "RST";
        case TCP_WHAT_FIN:
            return "FIN";
        case TCP_WHAT_ACK:
            return "ACK";
        case TCP_WHAT_DATA:
            return "DATA";
        default:
            return "UNKN_WHAT";
    }
}

/***************************************************************************
 * This function could be used without TCB.
 * So we could start any conn from any TCP Conn Table.
 ***************************************************************************/
static void _tcpcon_send_raw_SYN(TCP_Table *tcpcon, ipaddress ip_them,
                                 unsigned port_them, ipaddress ip_me,
                                 unsigned port_me, uint32_t seqno_me) {
    PktBuf *response = 0;

    assert(ip_me.version != 0 && ip_them.version != 0);

    response = stack_get_pktbuf(tcpcon->stack);

    response->length = tcp_create_by_template(
        tcpcon->syn_template, ip_them, port_them, ip_me, port_me, seqno_me, 0,
        TCP_FLAG_SYN, 0, 0, NULL, 0, response->px, sizeof(response->px));

    stack_transmit_pktbuf(tcpcon->stack, response);
}

/***************************************************************************
 * Called upon timeouts when an acknowledgement hasn't been received in
 * time. Will resend the segments.
 *
 * NOTE: The conn is anomaly and should be close if returned false.
 ***************************************************************************/
static bool _tcb_seg_resend(TCP_Table *tcpcon, TCB *tcb) {
    TcpSegment *seg = tcb->segments;

    if (seg) {
        /*just handle packets with data (no data could be impossible)*/
        if (!seg->length || !seg->buf) {
            ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(tcb->ip_them);
            LOG(LEVEL_WARN,
                "tcp.seqno: (%s %u) cannot resend packet without data, conn "
                "will be closed.    \n",
                ip_them_fmt.string, tcb->port_them);
            return false;
        }

        if (tcb->seqno_me != seg->seqno) {
            ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(tcb->ip_them);
            LOG(LEVEL_WARN,
                "tcp.seqno: (%s %u) failed in diff=%d, conn will be closed.    "
                "\n",
                ip_them_fmt.string, tcb->port_them, tcb->seqno_me - seg->seqno);
            return false;
        }

        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_PSH | TCP_FLAG_ACK, seg->buf,
                            seg->length);
    }

    return true;
}

/***************************************************************************
 ***************************************************************************/
static void _application_notify(TCP_Table *tcpcon, TCB *tcb, AppEvent event,
                                const void *payload, size_t payload_length,
                                unsigned secs, unsigned usecs) {
    TCP_Stack socket = {
        .tcpcon = tcpcon, .tcb = tcb, .secs = secs, .usecs = usecs};

    application_event(&socket, event, payload, payload_length);
}

/***************************************************************************
 * !cannot do sending data and closing at same time
 * if set closing, we would ignore the data.
 ***************************************************************************/
static void _tcb_seg_send(TCP_Table *tcpcon, TCB *tcb, const void *buf,
                          size_t length, unsigned is_dynamic) {
    if (!buf || !length)
        return;

    TcpSegment  *seg;
    TcpSegment **next;
    unsigned     seqno       = tcb->seqno_me;
    size_t       length_more = 0;

    if (length > tcb->mss) {
        length_more = length - tcb->mss;
        length      = tcb->mss;
    }

    /* Go to the end of the segment list */
    for (next = &tcb->segments; *next; next = &(*next)->next) {
        seqno = (unsigned)((*next)->seqno + (*next)->length);
    }

    /* Append this segment to the list */
    seg   = CALLOC(1, sizeof(*seg));
    *next = seg;

    seg->seqno      = seqno;
    seg->length     = length;
    seg->is_dynamic = is_dynamic;
    seg->buf        = (unsigned char *)buf;

    if (tcb->tcpstate != STATE_SENDING)
        _application_notify(tcpcon, tcb, APP_WHAT_SENDING, seg->buf,
                            seg->length, 0, 0);

    /* If this is the head of the segment list, then transmit right away */
    if (tcb->segments == seg) {
        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_PSH | TCP_FLAG_ACK, seg->buf,
                            seg->length);
        _tcb_change_state_to(tcb, STATE_SENDING);
    }

    /* If the input buffer was too large to fit a single segment, then
     * split it up into multiple segments */
    if (length_more) {
        void *buf_more = MALLOC(length_more);
        memcpy(buf_more, (unsigned char *)buf + length, length_more);
        _tcb_seg_send(tcpcon, tcb, buf_more, length_more, 1);
    }
}

/***************************************************************************
 * @return true for good ack.
 *
 * NOTE: conn may not be anomaly even returned false.
 ***************************************************************************/
static bool _tcp_seg_acknowledge(TCB *tcb, uint32_t ackno) {
    /* Normal: just discard repeats */
    if (ackno == tcb->seqno_me) {
        return false;
    }

    /* Make sure this isn't a duplicate ACK from past
     * WRAPPING of 32-bit arithmetic happens here */
    if (ackno - tcb->seqno_me > 100000) {
        ipaddress_formatted_t fmt = ipaddress_fmt(tcb->ip_them);
        LOG(LEVEL_DEBUG,
            "tcp.tcb: (%s %u) "
            "ackno from past: "
            "old ackno = 0x%08x, this ackno = 0x%08x\n",
            fmt.string, tcb->port_them, tcb->ackno_me, ackno);
        return false;
    }

    /* Make sure this isn't invalid ACK from the future
     * WRAPPING of 32-bit arithmetic happens here */
    if (tcb->seqno_me - ackno < 100000) {
        ipaddress_formatted_t fmt = ipaddress_fmt(tcb->ip_them);
        LOG(LEVEL_DEBUG,
            "tcp.tcb: (%s %u) "
            "ackno from future: "
            "my seqno = 0x%08x, their ackno = 0x%08x\n",
            fmt.string, tcb->port_them, tcb->seqno_me, ackno);
        return false;
    }

    /*
    !Retire outstanding segments
    */
    {
        unsigned length = ackno - tcb->seqno_me;
        while (tcb->segments && length >= tcb->segments->length) {
            TcpSegment *seg = tcb->segments;
            assert(seg->buf);

            tcb->segments = seg->next;
            tcb->seqno_me += seg->length;
            length -= seg->length;

            _LOGtcb(tcb, 1, "ACKed %u-bytes\n", seg->length);

            /* free the old segment */
            if (seg->is_dynamic) {
                FREE(seg->buf);
            }
            FREE(seg);
            if (ackno == tcb->seqno_me)
                return true; /* all outstanding data acknowledged */
        }

        if (tcb->segments && length < tcb->segments->length) {
            TcpSegment *seg = tcb->segments;
            assert(seg->buf);

            tcb->seqno_me += length;
            _LOGtcb(tcb, 1, "ACKed %u-bytes\n", length);

            /* This segment needs to be reduced */
            if (seg->is_dynamic) {
                size_t         new_length = seg->length - length;
                unsigned char *buf        = MALLOC(new_length);

                memcpy(buf, seg->buf + length, new_length);
                FREE(seg->buf);

                seg->buf        = buf;
                seg->length     = new_length;
                seg->is_dynamic = 1;
            } else {
                seg->buf += length;
                seg->length -= length;
            }
        }
    }

    /* Mark that this was a good ack */
    return true;
}

/***************************************************************************
 ***************************************************************************/
SockRes tcpapi_set_timeout(TCP_Stack *socket, unsigned secs, unsigned usecs) {
    if (socket == NULL || socket->tcb == NULL)
        return SOCKERR_EBADF;

    TCP_Table *tcpcon = socket->tcpcon;
    TCB       *tcb    = socket->tcb;

    timeouts_add(tcpcon->timeouts, tcb->timeout, offsetof(TCB, timeout),
                 TICKS_FROM_TV(socket->secs + secs, socket->usecs + usecs));
    return SOCKERR_NONE;
}

/***************************************************************************
 ***************************************************************************/
SockRes tcpapi_recv(TCP_Stack *socket) {
    TCB *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;
    tcb = socket->tcb;

    switch (tcb->tcpstate) {
        default:
        case STATE_SENDING:
            _tcb_change_state_to(socket->tcb, STATE_RECVING);
            break;
    }
    return SOCKERR_NONE;
}

/***************************************************************************
 ***************************************************************************/
SockRes tcpapi_send_data(TCP_Stack *socket, const void *buf, size_t length,
                         unsigned is_dynamic) {
    /*no data*/
    if (!buf || !length)
        return 1;

    TCB *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;

    tcb = socket->tcb;
    switch (tcb->tcpstate) {
        case STATE_RECVING:
            _tcb_change_state_to(tcb, STATE_SENDING);
            /*follow through*/
        case STATE_SENDING:
            _tcb_seg_send(socket->tcpcon, tcb, buf, length, is_dynamic);
            return SOCKERR_NONE;
        default: {
            ipaddress_formatted_t fmt = ipaddress_fmt(tcb->ip_them);
            LOG(LEVEL_WARN, "tcp.app: (%s %u) attempted SEND in wrong state\n",
                fmt.string, tcb->port_them);
            return SOCKERR_EBADF;
        }
    }
}

/***************************************************************************
 ***************************************************************************/
SockRes tcpapi_change_app_state(TCP_Stack *socket, AppState new_app_state) {
    TCB *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;

    tcb = socket->tcb;

    tcb->app_state = new_app_state;
    return SOCKERR_NONE;
}

/***************************************************************************
 ***************************************************************************/
SockRes tcpapi_close(TCP_Stack *socket) {
    if (socket == NULL || socket->tcb == NULL)
        return SOCKERR_EBADF;

    TCB *tcb = socket->tcb;

    _tcpcon_send_packet(socket->tcpcon, tcb, TCP_FLAG_RST, 0, 0);
    _tcpcon_destroy_tcb(socket->tcpcon, tcb, Reason_Close);

    /* The TCB is now on the table's freed-list. Do not leave a dangling
     * pointer in the per-connection API handle. */
    socket->tcb = NULL;

    return SOCKERR_NONE;
}

/***************************************************************************
 ***************************************************************************/

static void _LOGSEND(TCB *tcb, const char *what) {
    if (tcb == NULL)
        return;
    LOGip(5, tcb->ip_them, tcb->port_them, "=%s : --->> %s                  \n",
          _tcp_state_to_string(tcb->tcpstate), what);
}

/***************************************************************************
 ***************************************************************************/
static int _tcb_seg_recv(TCP_Table *tcpcon, TCB *tcb,
                         const unsigned char *payload, size_t payload_length,
                         unsigned seqno_them, unsigned secs, unsigned usecs) {
    if ((tcb->seqno_them - seqno_them) > payload_length) {
        _LOGSEND(tcb, "peer(ACK) [acknowledge payload 1]");
        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
        return 1;
    }

    while (seqno_them != tcb->seqno_them && payload_length) {
        seqno_them++;
        payload_length--;
        payload++;
    }

    if (payload_length == 0) {
        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
        return 1;
    }

    _LOGtcb(tcb, 2, "received %u bytes\n", payload_length);

    tcb->seqno_them += payload_length;

    /* Send ack for the data */
    _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);

    _application_notify(tcpcon, tcb, APP_WHAT_RECV_PAYLOAD, payload,
                        payload_length, secs, usecs);

    return 0;
}

/*****************************************************************************
 * Handles incoming events, like timeouts and packets, that cause a change
 * in the TCP control block "state".
 *****************************************************************************/
void stack_incoming_tcp(TCP_Table *tcpcon, TCB *tcb, TcpWhat what,
                        const unsigned char *payload, size_t payload_length,
                        unsigned secs, unsigned usecs, unsigned seqno_them,
                        unsigned ackno_them) {
    /* A TCP segment larger than the packet buffer is malformed for this
     * stack; drop it instead of asserting (Debug) or continuing with
     * undefined assumptions (Release). */
    if (payload_length >= 2000) {
        LOG(LEVEL_WARN,
            "tcp.seqno: dropping oversized TCP payload (%u bytes)\n",
            (unsigned)payload_length);
        return;
    }

    /* FILTER
     * Reject out-of-order payloads
     * NOTE: payload and ACK are handled seperately
     */
    if (payload_length) {
        int payload_offset = seqno_them - tcb->seqno_them;
        if (payload_offset < 0) {
            /* This is a retransmission that we've already acknowledged */
            if (payload_offset <= 0 - (int)payload_length) {
                /* Both begin and end are old, so simply discard it */
                return;
            } else {
                /* Otherwise shorten the payload */
                payload_length += payload_offset;
                payload -= payload_offset;
                seqno_them -= payload_offset;
            }
        } else if (payload_offset > 0) {
            /* This is an out-of-order fragment in the future. an important
             * design of this light-weight stack is that we don't support this,
             * and force the other side to retransmit such packets */
            return;
        }
    }

    /* FILTER:
     * Reject out-of-order FINs.
     * Handle duplicate FINs here
     */
    if (what == TCP_WHAT_FIN) {
        if (seqno_them == tcb->seqno_them - 1) {
            /**Duplicate FIN(retransmission), respond with ACK.
             * Because our data may be sending.*/
            _LOGtcb(tcb, 1, "duplicate FIN\n");
            _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
            return;
        } else if (seqno_them != tcb->seqno_them) {
            /* out of order FIN, so drop it */
            _LOGtcb(tcb, 1, "out-of-order FIN\n");
            return;
        }
    }

    _LOGtcb(tcb, 1, "##%s##\n", _what_to_string(what));

    /* Make sure no connection lasts longer than specified seconds */
    if (what == TCP_WHAT_TIMEOUT) {
        if (tcb->when_created + tcpcon->expire < secs) {
            LOGip(LEVEL_DETAIL, tcb->ip_them, tcb->port_them,
                  "%s                \n", "CONNECTION TIMEOUT---");
            _LOGSEND(tcb, "peer(RST)");
            _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
            _tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
            return;
        }
    }

    /*passive closed by target host's RST*/
    if (what == TCP_WHAT_RST) {
        _LOGSEND(tcb, "tcb(destroy)");
        _tcpcon_destroy_tcb(tcpcon, tcb, Reason_RST);
        return;
    }

    switch (tcb->tcpstate) {
        case STATE_SYNSENT: {
            switch (what) {
                case TCP_WHAT_TIMEOUT:
                    _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_SYN, NULL, 0);
                    tcb->syns_sent++;
                    break;
                case TCP_WHAT_SYNACK:
                    tcb->seqno_them       = seqno_them;
                    tcb->seqno_them_first = seqno_them - 1;
                    tcb->seqno_me         = ackno_them;
                    tcb->seqno_me_first   = ackno_them - 1;

                    _LOGtcb(tcb, 1, "%s connection established\n",
                            _what_to_string(what));

                    _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);

                    /*********** Connection Established From Here.*************/

                    _tcb_change_state_to(tcb, STATE_RECVING);

                    /*do connection init for probe*/
                    ProbeTarget target = {
                        .target.ip_proto  = IP_PROTO_TCP,
                        .target.ip_them   = tcb->ip_them,
                        .target.port_them = tcb->port_them,
                        .target.ip_me     = tcb->ip_me,
                        .target.port_me   = tcb->port_me,
                        /*Probe_TYPE State doesn't need cookie*/
                        .cookie           = 0,
                        .index = tcb->port_me - tcpcon->src_port_start,
                    };

                    if (!tcb->probe->conn_init_cb(&tcb->probe_state, &target)) {
                        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                        _tcpcon_destroy_tcb(tcpcon, tcb, Reason_FIN);
                        return;
                    }

                    _application_notify(tcpcon, tcb, APP_WHAT_CONNECTED, 0, 0,
                                        secs, usecs);

                    break;
                default:
                    LOGnet(tcb->ip_them, tcb->port_them,
                           "Unhandled Event>>> %s:%s\n",
                           _tcp_state_to_string(tcb->tcpstate),
                           _what_to_string(what));

                    break;
            }
            break;
        }

        case STATE_SENDING: {
            switch (what) {
                case TCP_WHAT_FIN:
                    if (seqno_them == tcb->seqno_them) {
                        /* I have ACKed all their data, so therefore process
                         * this */
                        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                        _tcpcon_destroy_tcb(tcpcon, tcb, Reason_FIN);
                    } else {
                        /* I haven't received all their data, so ignore it until
                         * I do
                         */
                        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
                    }
                    break;
                case TCP_WHAT_ACK:
                    _tcp_seg_acknowledge(tcb, ackno_them);

                    if (tcb->segments == NULL || tcb->segments->length == 0) {
                        /* We've finished sending everything */
                        _tcb_change_state_to(tcb, STATE_RECVING);

                        /* All the payload has been sent. Notify the application
                         * of this, so that they can send more if the want, or
                         * switch to listening. */
                        _application_notify(tcpcon, tcb, APP_WHAT_SEND_SENT, 0,
                                            0, secs, usecs);
                    }
                    break;
                case TCP_WHAT_TIMEOUT:
                    if (!_tcb_seg_resend(tcpcon, tcb)) {
                        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                        _tcpcon_destroy_tcb(tcpcon, tcb, Reason_Anomaly);
                    }

                    break;
                case TCP_WHAT_DATA:
                    /* We don't receive data while in the sending state. We
                     * force them to keep re-sending it until we are prepared to
                     * receive it. This saves us from having to buffer it in
                     * this stack. */
                    break;
                case TCP_WHAT_SYNACK:
                    /** A delayed SYN-ACK.
                     * It can be solved by our pkt sending if it's a
                     * retransmission for lost ACK.
                     */
                    break;
                default:
                    LOGnet(tcb->ip_them, tcb->port_them,
                           "Unhandled Event>>> %s:%s\n",
                           _tcp_state_to_string(tcb->tcpstate),
                           _what_to_string(what));
                    break;
            }
            break;
        }

        case STATE_RECVING: {
            switch (what) {
                case TCP_WHAT_FIN:
                    if (seqno_them == tcb->seqno_them) {
                        /* I have ACKed all their data, so therefore process
                         * this */
                        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_RST, 0, 0);
                        _tcpcon_destroy_tcb(tcpcon, tcb, Reason_FIN);
                    } else {
                        /* I haven't received all their data, so ignore it until
                         * I do
                         */
                        _tcpcon_send_packet(tcpcon, tcb, TCP_FLAG_ACK, 0, 0);
                    }
                    break;
                case TCP_WHAT_ACK:
                    _tcp_seg_acknowledge(tcb, ackno_them);
                    break;
                case TCP_WHAT_TIMEOUT:
                    _application_notify(tcpcon, tcb, APP_WHAT_RECV_TIMEOUT, 0,
                                        0, secs, usecs);
                    break;
                case TCP_WHAT_DATA:
                    _tcb_seg_recv(tcpcon, tcb, payload, payload_length,
                                  seqno_them, secs, usecs);
                    break;
                case TCP_WHAT_SYNACK:
                    /** A delayed SYN-ACK.
                     * Maybe a retransmission for lost ACK?
                     * But our stack can't identify it, just give up.
                     */
                    break;
                default:
                    LOGnet(tcb->ip_them, tcb->port_them,
                           "Unhandled Event>>> %s:%s\n",
                           _tcp_state_to_string(tcb->tcpstate),
                           _what_to_string(what));
                    break;
            }
            break;
        }

        default: {
            LOGnet(tcb->ip_them, tcb->port_them, "Unhandled Event>>> %s:%s\n",
                   _tcp_state_to_string(tcb->tcpstate), _what_to_string(what));
            break;
        }
    }

    return;
}

/***************************************************************************
 ***************************************************************************/
static const char *_app_state_to_string(unsigned state) {
    switch (state) {
        case APP_STATE_INIT:
            return "INIT";
        case APP_STATE_RECV_HELLO:
            return "RECV_HELLO";
        case APP_STATE_RECVING:
            return "RECVING";
        case APP_STATE_SEND_FIRST:
            return "SEND_FIRST";
        case APP_STATE_SENDING:
            return "SENDING";
        default:
            return "unknown";
    }
}

/***************************************************************************
 ***************************************************************************/
static const char *_event_to_string(AppEvent ev) {
    switch (ev) {
        case APP_WHAT_CONNECTED:
            return "CONNECTED";
        case APP_WHAT_RECV_TIMEOUT:
            return "RECV_TIMEOUT";
        case APP_WHAT_RECV_PAYLOAD:
            return "RECV_PAYLOAD";
        case APP_WHAT_SEND_SENT:
            return "SEND_SENT";
        case APP_WHAT_SENDING:
            return "SENDING";
        default:
            return "unknown";
    }
}

/***************************************************************************
 ***************************************************************************/
void application_event(TCP_Stack *socket, AppEvent cur_event,
                       const void *payload, size_t payload_length) {
    AppState     cur_state = socket->tcb->app_state;
    const Probe *probe     = socket->tcb->probe;

again:
    switch (cur_state) {
        case APP_STATE_INIT: {
            switch (cur_event) {
                case APP_WHAT_CONNECTED:
                    if (probe->hello_wait <= 0) {
                        tcpapi_change_app_state(socket, APP_STATE_SEND_FIRST);
                        cur_state = APP_STATE_SEND_FIRST;
                        goto again;
                    } else {
                        tcpapi_set_timeout(socket, probe->hello_wait, 0);
                        tcpapi_recv(socket);
                        tcpapi_change_app_state(socket, APP_STATE_RECV_HELLO);
                    }
                    break;
                default: {
                    ipaddress_formatted_t fmt =
                        ipaddress_fmt(socket->tcb->ip_them);
                    LOG(LEVEL_WARN,
                        "tcp.app: (%s %u) unhandled event: state=%s event=%s\n",
                        fmt.string, socket->tcb->port_them,
                        _app_state_to_string(cur_state),
                        _event_to_string(cur_event));
                    break;
                }
            }
            break;
        }

        case APP_STATE_RECV_HELLO: {
            switch (cur_event) {
                case APP_WHAT_RECV_TIMEOUT:
                    /* We've got no response from the initial connection,
                     * so switch from them being responsible for communications
                     * to us being responsible, and start sending */
                    tcpapi_change_app_state(socket, APP_STATE_SEND_FIRST);
                    cur_state = APP_STATE_SEND_FIRST;
                    goto again;
                    break;
                case APP_WHAT_RECV_PAYLOAD:
                    /* We've receive some data from them, so wait for some more.
                     * This means we won't be transmitting anything to them. */
                    tcpapi_change_app_state(socket, APP_STATE_RECVING);
                    cur_state = APP_STATE_RECVING;
                    goto again;
                default: {
                    ipaddress_formatted_t fmt =
                        ipaddress_fmt(socket->tcb->ip_them);
                    LOG(LEVEL_WARN,
                        "tcp.app: (%s %u) unhandled event: state=%s event=%s\n",
                        fmt.string, socket->tcb->port_them,
                        _app_state_to_string(cur_state),
                        _event_to_string(cur_event));
                    break;
                }
            }
            break;
        }

        case APP_STATE_RECVING: {
            switch (cur_event) {
                case APP_WHAT_RECV_PAYLOAD: {
                    ProbeTarget target = {
                        .target.ip_proto  = IP_PROTO_TCP,
                        .target.ip_them   = socket->tcb->ip_them,
                        .target.ip_me     = socket->tcb->ip_me,
                        .target.port_them = socket->tcb->port_them,
                        .target.port_me   = socket->tcb->port_me,
                        /*state mode does not need cookie*/
                        .cookie           = 0,
                        .index            = socket->tcb->port_me -
                                 socket->tcpcon->src_port_start,
                    };

                    DataPass pass = {0};

                    unsigned is_multi = probe->parse_response_cb(
                        &pass, &socket->tcb->probe_state,
                        socket->tcpcon->out_conf, &target,
                        (const unsigned char *)payload, payload_length);

                    /**
                     * Split the semantic of DataPass into Sending Data &
                     * Closing. Because our TCP API just handle one of each at a
                     * time.
                     * */
                    if (pass.len)
                        tcpapi_send_data(socket, pass.data, pass.len,
                                         pass.is_dynamic);
                    if (pass.is_close)
                        tcpapi_close(socket);

                    /**
                     * multi-probe Multi_AfterHandle.
                     * we use ip info from target because tcb maybe destroyed
                     * now
                     * */
                    if (probe->multi_mode == Multi_AfterHandle && is_multi &&
                        target.target.port_me ==
                            socket->tcpcon->src_port_start) {
                        for (unsigned idx = 1; idx < probe->multi_num; idx++) {
                            unsigned cookie = get_cookie(
                                target.target.ip_them, target.target.port_them,
                                target.target.ip_me,
                                socket->tcpcon->src_port_start + idx,
                                socket->tcpcon->entropy);

                            _tcpcon_send_raw_SYN(
                                socket->tcpcon, target.target.ip_them,
                                target.target.port_them, target.target.ip_me,
                                socket->tcpcon->src_port_start + idx, cookie);
                        }
                    }

                    /**
                     * multi-probe Multi_DynamicNext
                     * we use ip info from target because tcb maybe destroyed
                     * now
                     * */
                    if (probe->multi_mode == Multi_DynamicNext && is_multi) {
                        unsigned cookie = get_cookie(
                            target.target.ip_them, target.target.port_them,
                            target.target.ip_me,
                            socket->tcpcon->src_port_start + is_multi - 1,
                            socket->tcpcon->entropy);

                        _tcpcon_send_raw_SYN(
                            socket->tcpcon, target.target.ip_them,
                            target.target.port_them, target.target.ip_me,
                            socket->tcpcon->src_port_start + is_multi - 1,
                            cookie);
                    }

                    break;
                }
                case APP_WHAT_RECV_TIMEOUT:
                    /** FIXME:
                     * RECV_HELLO can transit to SEND_FIRST by timeout, because
                     * we have make_hello interface. But this cannot handled
                     * well, so we cannot set socket to wait mode after hello
                     * said. And it leads to no hello wait when probe nested
                     * like tls-state*/
                    break;
                case APP_WHAT_SENDING:
                    /* A higher level protocol has started sending packets while
                     * processing a receive, therefore, change to the SEND state
                     */
                    tcpapi_change_app_state(socket, APP_STATE_SENDING);
                    break;
                case APP_WHAT_SEND_SENT:
                    /* FIXME */
                    break;
                default: {
                    ipaddress_formatted_t fmt =
                        ipaddress_fmt(socket->tcb->ip_them);
                    LOG(LEVEL_WARN,
                        "tcp.app: (%s %u) unhandled event: state=%s event=%s\n",
                        fmt.string, socket->tcb->port_them,
                        _app_state_to_string(cur_state),
                        _event_to_string(cur_event));
                    break;
                }
            }
            break;
        }

        case APP_STATE_SEND_FIRST: {
            ProbeTarget target = {
                .target.ip_proto  = IP_PROTO_TCP,
                .target.ip_them   = socket->tcb->ip_them,
                .target.port_them = socket->tcb->port_them,
                .target.ip_me     = socket->tcb->ip_me,
                .target.port_me   = socket->tcb->port_me,
                .cookie           = 0, /*does not support cookie now*/
                .index = socket->tcb->port_me - socket->tcpcon->src_port_start,
            };

            DataPass pass = {0};

            probe->make_hello_cb(&pass, &socket->tcb->probe_state, &target);

            /**
             * Split the semantic of DataPass into Sending Data & Closing.
             * Because our TCP API just handle one of each at a time.
             * */
            if (pass.len)
                tcpapi_send_data(socket, pass.data, pass.len, pass.is_dynamic);
            if (pass.is_close) {
                tcpapi_close(socket);
                break;
            }

            if (pass.len)
                tcpapi_change_app_state(socket, APP_STATE_SENDING);
            else
                tcpapi_change_app_state(socket, APP_STATE_RECVING);
            break;
        }

        case APP_STATE_SENDING: {
            switch (cur_event) {
                case APP_WHAT_SEND_SENT:
                    /* We've got an acknowledgement that all our data
                     * was sent. Therefore, change the receive state */
                    tcpapi_recv(socket);
                    tcpapi_change_app_state(socket, APP_STATE_RECVING);
                    break;
                case APP_WHAT_SENDING:
                    break;
                default: {
                    ipaddress_formatted_t fmt =
                        ipaddress_fmt(socket->tcb->ip_them);
                    LOG(LEVEL_WARN,
                        "tcp.app: (%s %u) unhandled event: state=%s event=%s\n",
                        fmt.string, socket->tcb->port_them,
                        _app_state_to_string(cur_state),
                        _event_to_string(cur_event));
                    break;
                }
            }
            break;
        }

        default: {
            ipaddress_formatted_t fmt = ipaddress_fmt(socket->tcb->ip_them);
            LOG(LEVEL_WARN,
                "tcp.app: (%s %u) unhandled event: state=%s event=%s\n",
                fmt.string, socket->tcb->port_them,
                _app_state_to_string(cur_state), _event_to_string(cur_event));
            break;
        }
    }
}

/***************************************************************************
 * Regression tests for the TCP segment acknowledgement bookkeeping and the
 * NULL-safe API entry points. Exposed for --selftest.
 ***************************************************************************/
int tcp_seg_ack_selftest(void) {
#define TCP_SELFTEST_CHECK(cond, step)                                        \
    do {                                                                      \
        if (!(cond)) {                                                        \
            LOG(LEVEL_ERROR, "tcp_seg_ack_selftest failed at step %d\n",      \
                step);                                                        \
            return 1;                                                         \
        }                                                                     \
    } while (0)

    TCB tcb;
    memset(&tcb, 0, sizeof(tcb));
    tcb.ip_them.version = 4;
    tcb.ip_them.ipv4    = 0x01020304;
    tcb.port_them       = 80;
    tcb.seqno_me        = 1000;

    TcpSegment *s1 = CALLOC(1, sizeof(TcpSegment));
    TcpSegment *s2 = CALLOC(1, sizeof(TcpSegment));
    unsigned char b1[128];
    unsigned char b2[128];

    s1->buf      = b1;
    s1->length   = 100;
    s1->seqno    = 1000;
    s2->buf      = b2;
    s2->length   = 50;
    s2->seqno    = 1100;
    s1->next     = s2;
    tcb.segments = s1;

    TCP_SELFTEST_CHECK(_tcp_seg_acknowledge(&tcb, 1050), 1);
    TCP_SELFTEST_CHECK(tcb.seqno_me == 1050 && tcb.segments == s1 &&
                           s1->length == 50,
                       2);

    TCP_SELFTEST_CHECK(_tcp_seg_acknowledge(&tcb, 1100), 3);
    TCP_SELFTEST_CHECK(tcb.seqno_me == 1100 && tcb.segments == s2, 4);

    TCP_SELFTEST_CHECK(_tcp_seg_acknowledge(&tcb, 1150), 5);
    TCP_SELFTEST_CHECK(tcb.seqno_me == 1150 && tcb.segments == NULL, 6);

    TCP_SELFTEST_CHECK(!_tcp_seg_acknowledge(&tcb, 1150), 7);

    TCP_SELFTEST_CHECK(tcpapi_set_timeout(NULL, 1, 0) == SOCKERR_EBADF, 8);
    TCP_SELFTEST_CHECK(tcpapi_close(NULL) == SOCKERR_EBADF, 9);

    return 0;
#undef TCP_SELFTEST_CHECK
}