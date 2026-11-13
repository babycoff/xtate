#ifndef XTATE_SECURE_RANDOM_H
#define XTATE_SECURE_RANDOM_H

#include <stddef.h>

/*
 * Fill buf with cryptographically secure random bytes.
 * Returns 1 on success, 0 on failure.
 *
 * Uses OpenSSL when available, BCryptGenRandom on Windows without OpenSSL,
 * and /dev/urandom on other platforms without OpenSSL.
 */
int secure_random_bytes(unsigned char *buf, size_t len);

#endif
