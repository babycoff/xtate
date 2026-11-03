#include "probe-modules.h"

#include <string.h>

#include "../xconf.h"
#include "../output-modules/output-modules.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

#define GET_STATE_PAYLOAD "GET / HTTP/1.0\r\n\r\n"

/*for internal x-ref*/
extern Probe GetStateProbe;

struct GetStateConf {
    unsigned get_whole_page : 1;
};

static struct GetStateConf getstate_conf = {0};

static ConfRes SET_whole_page(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    getstate_conf.get_whole_page = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam getstate_parameters[] = {
    {"whole-page",
     SET_whole_page,
     Type_FLAG,
     {"whole", 0},
     "Get the whole page before connection timeout, not just the banner."},

    {0}};

static bool getstate_init(const XConf *xconf) {
    LOG(LEVEL_INFO, "(GetState Probe global initing) >>>\n");
    return true;
}

static void getstate_close() {
    LOG(LEVEL_INFO, "(GetState Probe closing) >>>\n");
}

static bool getstate_conn_init(ProbeState *state, ProbeTarget *target) {
    LOG(LEVEL_INFO, "(GetState Probe conn initing) >>>\n");
    return true;
}

static void getstate_conn_close(ProbeState *state, ProbeTarget *target) {
    LOG(LEVEL_INFO, "(GetState Probe conn closing) >>>\n");
}

static void getstate_make_hello(DataPass *pass, ProbeState *state,
                                ProbeTarget *target) {
    LOG(LEVEL_INFO, "(GetState Probe making hello) >>>\n");
    /*static data and don't close the conn*/
    datapass_set_data(pass, (unsigned char *)GET_STATE_PAYLOAD,
                      strlen(GET_STATE_PAYLOAD), false);
}

static unsigned getstate_parse_response(DataPass *pass, ProbeState *state,
                                        OutConf *out, ProbeTarget *target,
                                        const unsigned char *px,
                                        unsigned             sizeof_px) {
    LOG(LEVEL_INFO, "(GetState Probe parsing response) >>>\n");
    if (state->state)
        return 0;

    if (!getstate_conf.get_whole_page) {
        state->state   = 1;
        pass->is_close = 1;
    }

    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .level            = OUT_SUCCESS,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };

    dach_append_banner(&item.probe_report, "banner", px, sizeof_px);

    output_result(out, &item);

    return 0;
}

Probe GetStateProbe = {
    .name       = "get-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .params     = getstate_parameters,
    .short_desc = "A probe that sends HTTP GET request to test and debug "
                  "stateful TCP scan",
    .desc = "GetState Probe sends target port a simple HTTP GET request:\n"
            "    `GET / HTTP/1.0\\r\\n\\r\\n`\n"
            "And could get a simple result from http server fastly. GetState "
            "is the state version of GetRequest Probe for testing ScanModules "
            "that needs a probe of state type.",

    .init_cb           = &getstate_init,
    .conn_init_cb      = &getstate_conn_init,
    .make_hello_cb     = &getstate_make_hello,
    .parse_response_cb = &getstate_parse_response,
    .conn_close_cb     = &getstate_conn_close,
    .close_cb          = &getstate_close,
};