#ifndef XTATE_CAPABILITIES_H
#define XTATE_CAPABILITIES_H

#ifdef __cplusplus
extern "C" {
#endif

/* Machine-readable build and module capabilities for agent hosts and UIs.
 * Returns malloc'd JSON text, or NULL if the module catalog cannot be read. */
char *capabilities_json(void);

#ifdef __cplusplus
}
#endif

#endif
