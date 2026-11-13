#ifndef XTATE_GUI_H
#define XTATE_GUI_H

/*
 * Xtate GUI: a loopback-only HTTP control-plane client.
 *
 * The embedded page is a presentation layer only. Every action is forwarded
 * to the control plane over its local JSON-lines protocol; the GUI never
 * starts a scanner in-process and never reads result records directly.
 */
int gui_run(const char *endpoint, const char *listen);

#endif
