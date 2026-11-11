#ifndef RESULT_STORE_H
#define RESULT_STORE_H
#include <stdint.h>
#include <stdbool.h>
/* Split result_path into result-00001.ndjson chunks when chunk_bytes>0.
 * Writes <result>.manifest.json and optional <result>.index.json. */
int result_store_build(const char *result_path, uint64_t chunk_bytes,
                       bool build_index);
#endif
