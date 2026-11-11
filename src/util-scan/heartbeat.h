#ifndef HEARTBEAT_H
#define HEARTBEAT_H
#include <stdint.h>
void heartbeat_write(const char *path, uint64_t sent, uint64_t targets,
                     uint64_t success, uint64_t failed, uint64_t info,
                     const char *phase);
#endif
