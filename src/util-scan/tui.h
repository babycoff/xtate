#ifndef TUI_H
#define TUI_H

/**
 * Run the full-screen control-plane dashboard.
 *
 * The TUI is a thin client: it never scans in-process. It connects to a
 * running control plane endpoint and drives jobs through job.list,
 * job.status, job.start, job.cancel and job.result_manifest.
 *
 * When stdin or stdout is not a terminal, a one-shot plain-text snapshot is
 * printed instead. This keeps the command usable from scripts and CI.
 */
int tui_run(const char *endpoint);

#endif
