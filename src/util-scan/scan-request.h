#ifndef SCAN_REQUEST_H
#define SCAN_REQUEST_H
#include <stdbool.h>
unsigned scan_request_timeout(const char *filename);
int scan_request_build_argv(const char *filename, int *argc_out,
                            char ***argv_out);
#endif
