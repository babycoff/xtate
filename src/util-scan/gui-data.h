#ifndef XTATE_GUI_DATA_H
#define XTATE_GUI_DATA_H

#include <stddef.h>

/*
    Structured data for the 3.0 GUI.

    These functions return heap-allocated JSON text. The caller owns the
    returned buffer and frees it with free(). NULL means the data could not be
    collected; the caller should return an API error rather than a fake empty
    list.
*/

char *gui_system_json(const char *endpoint);
char *gui_interfaces_json(void);
char *gui_options_json(void);

/*
    Validate a scan request without sending a packet.  The request body is
    {"targets":"...","ports":"80,443","scan":"tcp-syn","probe":"http",
     "rate":1000,"timeout_sec":300,"interface":"optional device name"}.

    The result is {"ok":bool,"errors":[...],"warnings":[...],
    "targets":N,"ports":N,"attempts":N,"route_groups":N,"routes":[...],
    "interface":{...}} and is safe to show before the authorization gate.
*/
char *gui_preflight_json(const char *body);

#endif
