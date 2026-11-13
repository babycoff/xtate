#ifndef UI_CONTROL_H
#define UI_CONTROL_H

#include <stddef.h>

/*
 * Start a private control plane for a local TUI/GUI process.
 *
 * The child is the same executable with --control-plane=<endpoint>.  The
 * endpoint is filled by this function and is valid only while the child lives.
 * Returns 0 on success and leaves a stoppable child behind.
 */
int ui_control_start(const char *exe_path, char *endpoint, size_t endpoint_size);

/*
 * Stop the private control plane started by ui_control_start().  Safe to call
 * when no child was started.
 */
void ui_control_stop(void);

#endif
