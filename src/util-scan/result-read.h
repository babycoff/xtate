#ifndef XTATE_RESULT_READ_H
#define XTATE_RESULT_READ_H

#include <stddef.h>

/*
 * Read a bounded page of valid NDJSON records for a completed job.
 * Resolves the result path from the job manifest; the caller never supplies
 * an arbitrary file path. Returns heap JSON on success, NULL otherwise.
 * status is 200, 400 (invalid job id), 404 (no readable result) or 500.
 */
char *result_records_json(const char *endpoint, const char *job_id,
                          int offset, int limit, int *status);

#endif
