#include "error-code.h"
#include <stddef.h>

static const struct { ErrorCode code; const char *name; bool retryable; } k[] = {
    {ERR_INVALID_JSON,"INVALID_JSON",false},
    {ERR_INVALID_ARGUMENT,"INVALID_ARGUMENT",false},
    {ERR_UNSUPPORTED_SCAN,"UNSUPPORTED_SCAN",false},
    {ERR_UNSUPPORTED_PROBE,"UNSUPPORTED_PROBE",false},
    {ERR_TARGET_INVALID,"TARGET_INVALID",false},
    {ERR_PERMISSION_DENIED,"PERMISSION_DENIED",false},
    {ERR_FIREWALL_RULES_MISSING,"FIREWALL_RULES_MISSING",false},
    {ERR_OUTPUT_WRITE_FAILED,"OUTPUT_WRITE_FAILED",false},
    {ERR_IO_ERROR,"IO_ERROR",true},
    {ERR_CONFIG_ERROR,"CONFIG_ERROR",false},
    {ERR_SCAN_TIMEOUT,"SCAN_TIMEOUT",true},
    {ERR_SCAN_STALLED,"SCAN_STALLED",false},
    {ERR_SCAN_CANCELLED,"SCAN_CANCELLED",false},
    {ERR_JOB_NOT_FOUND,"JOB_NOT_FOUND",false},
    {ERR_JOB_ALREADY_RUNNING,"JOB_ALREADY_RUNNING",true},
    {ERR_JOB_LIMIT_REACHED,"JOB_LIMIT_REACHED",true},
    {ERR_UNSUPPORTED_OPERATION,"UNSUPPORTED_OPERATION",false},
    {ERR_NOT_FOUND,"NOT_FOUND",false},
    {ERR_INVALID_STATE,"INVALID_STATE",false},
    {ERR_INTERNAL_ERROR,"INTERNAL_ERROR",false},
};
const char *error_code_name(ErrorCode code) {
    for (size_t i=0;i<sizeof(k)/sizeof(k[0]);i++) if (k[i].code==code) return k[i].name;
    return "INTERNAL_ERROR";
}
bool error_code_retryable(ErrorCode code) {
    for (size_t i=0;i<sizeof(k)/sizeof(k[0]);i++) if (k[i].code==code) return k[i].retryable;
    return false;
}
