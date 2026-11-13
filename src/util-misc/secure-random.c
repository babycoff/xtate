#include "secure-random.h"

#ifndef NOT_FOUND_OPENSSL
#include <openssl/rand.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

int secure_random_bytes(unsigned char *buf, size_t len) {
    if (buf == NULL || len == 0)
        return 1;

#ifndef NOT_FOUND_OPENSSL
    return RAND_bytes(buf, (int)len) == 1;
#elif defined(_WIN32)
    while (len > 0) {
        ULONG chunk = len > 0x100000u ? 0x100000u : (ULONG)len;
        if (BCryptGenRandom(NULL, buf, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return 0;
        buf += chunk;
        len -= chunk;
    }
    return 1;
#else
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
            return 0;
        while (len > 0) {
            ssize_t n = read(fd, buf, len);
            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                close(fd);
                return 0;
            }
            buf += (size_t)n;
            len -= (size_t)n;
        }
        close(fd);
        return 1;
    }
#endif
}
