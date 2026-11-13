#ifndef SCAN_REQUEST_H
#define SCAN_REQUEST_H
#include <stdbool.h>
unsigned scan_request_timeout(const char *filename);
int scan_request_build_argv(const char *filename, int *argc_out,
                            char ***argv_out);

/*
    Global options that a GUI/MCP client may pass through global_args.
    Returns 1 when the name is a real, non-reserved global option, 0 otherwise.
    The allowlist rejects process-mode, file/script, output-path and
    control-plane options; those stay operator-only.
*/
int scan_request_global_arg_allowed(const char *name);
int scan_request_global_arg_is_flag(const char *name);
int scan_request_global_arg_value_valid(const char *name, const char *value);
#endif
