#ifndef DATA_CONVERT_H
#define DATA_CONVERT_H

#include <stdint.h>
#include <stdbool.h>

/*******************************************************************
  convert big endian or little endian to unsigned
 ********************************************************************/

#define BE_TO_U16(px) ((px)[0] << 8 | (px)[1])
#define BE_TO_U24(px) ((px)[0] << 16 | (px)[1] << 8 | (px)[2])
#define BE_TO_U32(px)                                                         \
    ((uint32_t)(px)[0] << 24 | (uint32_t)(px)[1] << 16 |                      \
     (uint32_t)(px)[2] << 8 | (uint32_t)(px)[3])
#define BE_TO_U64(px)                                                          \
    ((uint64_t)(px)[0] << 56 | (uint64_t)(px)[1] << 48 |                       \
     (uint64_t)(px)[2] << 40 | (uint64_t)(px)[3] << 32 |                       \
     (uint64_t)(px)[4] << 24 | (uint64_t)(px)[5] << 16 |                       \
     (uint64_t)(px)[6] << 8 | (uint64_t)(px)[7])

#define LE_TO_U16(px) ((px)[1] << 8 | (px)[0])
#define LE_TO_U32(px)                                                         \
    ((uint32_t)(px)[3] << 24 | (uint32_t)(px)[2] << 16 |                      \
     (uint32_t)(px)[1] << 8 | (uint32_t)(px)[0])

/*******************************************************************
  convert unsigned to big endian or little endian
 ********************************************************************/

static inline void U16_TO_BE(unsigned char *px, uint16_t num) {
    px[0] = (unsigned char)((num >> 8) & 0xFF);
    px[1] = (unsigned char)((num >> 0) & 0xFF);
}

static inline void U32_TO_BE(unsigned char *px, uint32_t num) {
    px[0] = (unsigned char)((num >> 24) & 0xFF);
    px[1] = (unsigned char)((num >> 16) & 0xFF);
    px[2] = (unsigned char)((num >> 8) & 0xFF);
    px[3] = (unsigned char)((num >> 0) & 0xFF);
}

static inline void U64_TO_BE(unsigned char *px, uint64_t num) {
    px[0] = (unsigned char)((num >> 56) & 0xFF);
    px[1] = (unsigned char)((num >> 48) & 0xFF);
    px[2] = (unsigned char)((num >> 40) & 0xFF);
    px[3] = (unsigned char)((num >> 32) & 0xFF);
    px[4] = (unsigned char)((num >> 24) & 0xFF);
    px[5] = (unsigned char)((num >> 16) & 0xFF);
    px[6] = (unsigned char)((num >> 8) & 0xFF);
    px[7] = (unsigned char)((num >> 0) & 0xFF);
}

static inline void U16_TO_LE(unsigned char *px, uint16_t num) {
    px[1] = (unsigned char)((num >> 8) & 0xFF);
    px[0] = (unsigned char)((num >> 0) & 0xFF);
}

static inline void U32_TO_LE(unsigned char *px, uint32_t num) {
    px[3] = (unsigned char)((num >> 24) & 0xFF);
    px[2] = (unsigned char)((num >> 16) & 0xFF);
    px[1] = (unsigned char)((num >> 8) & 0xFF);
    px[0] = (unsigned char)((num >> 0) & 0xFF);
}

static inline void U64_TO_LE(unsigned char *px, uint64_t num) {
    px[7] = (unsigned char)((num >> 56) & 0xFF);
    px[6] = (unsigned char)((num >> 48) & 0xFF);
    px[5] = (unsigned char)((num >> 40) & 0xFF);
    px[4] = (unsigned char)((num >> 32) & 0xFF);
    px[3] = (unsigned char)((num >> 24) & 0xFF);
    px[2] = (unsigned char)((num >> 16) & 0xFF);
    px[1] = (unsigned char)((num >> 8) & 0xFF);
    px[0] = (unsigned char)((num >> 0) & 0xFF);
}

/*******************************************************************
  is unsigned equal to big endian or little endian
 ********************************************************************/

static inline bool U16_EQUAL_TO_BE(const unsigned char *px, uint16_t num) {
    if (px[0] == (unsigned char)((num >> 8) & 0xFF) &&
        px[1] == (unsigned char)((num >> 0) & 0xFF))
        return true;
    return false;
}

static inline bool U32_EQUAL_TO_BE(const unsigned char *px, uint32_t num) {
    if (px[0] == (unsigned char)((num >> 24) & 0xFF) &&
        px[1] == (unsigned char)((num >> 16) & 0xFF) &&
        px[2] == (unsigned char)((num >> 8) & 0xFF) &&
        px[3] == (unsigned char)((num >> 0) & 0xFF))
        return true;
    return false;
}

static inline bool U64_EQUAL_TO_BE(const unsigned char *px, uint64_t num) {
    if (px[0] == (unsigned char)((num >> 56) & 0xFF) &&
        px[1] == (unsigned char)((num >> 48) & 0xFF) &&
        px[2] == (unsigned char)((num >> 40) & 0xFF) &&
        px[3] == (unsigned char)((num >> 32) & 0xFF) &&
        px[4] == (unsigned char)((num >> 24) & 0xFF) &&
        px[5] == (unsigned char)((num >> 16) & 0xFF) &&
        px[6] == (unsigned char)((num >> 8) & 0xFF) &&
        px[7] == (unsigned char)((num >> 0) & 0xFF))
        return true;
    return false;
}

static inline bool U16_EQUAL_TO_LE(const unsigned char *px, uint16_t num) {
    if (px[1] == (unsigned char)((num >> 8) & 0xFF) &&
        px[0] == (unsigned char)((num >> 0) & 0xFF))
        return true;
    return false;
}

static inline bool U32_EQUAL_TO_LE(const unsigned char *px, uint32_t num) {
    if (px[3] == (unsigned char)((num >> 24) & 0xFF) &&
        px[2] == (unsigned char)((num >> 16) & 0xFF) &&
        px[1] == (unsigned char)((num >> 8) & 0xFF) &&
        px[0] == (unsigned char)((num >> 0) & 0xFF))
        return true;
    return false;
}

static inline bool U64_EQUAL_TO_LE(const unsigned char *px, uint64_t num) {
    if (px[7] == (unsigned char)((num >> 56) & 0xFF) &&
        px[6] == (unsigned char)((num >> 48) & 0xFF) &&
        px[5] == (unsigned char)((num >> 40) & 0xFF) &&
        px[4] == (unsigned char)((num >> 32) & 0xFF) &&
        px[3] == (unsigned char)((num >> 24) & 0xFF) &&
        px[2] == (unsigned char)((num >> 16) & 0xFF) &&
        px[1] == (unsigned char)((num >> 8) & 0xFF) &&
        px[0] == (unsigned char)((num >> 0) & 0xFF))
        return true;
    return false;
}

#endif