#include "result-read.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto/crypto-json.h"
#include "../util-data/file-open.h"
#include "control-client.h"

static char *dup_str(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static int valid_job_id(const char *job_id) {
    const char *p;
    if (!job_id || strncmp(job_id, "job-", 4) != 0 || job_id[4] == 0) return 0;
    for (p = job_id + 4; *p; p++)
        if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

static char *job_result_path(const char *endpoint, const char *job_id) {
    JsonNode *root = json_mkobject();
    char *request = NULL;
    char response[65536];
    char *path = NULL;
    if (!root) return NULL;
    json_append_member(root, "id", json_mknumber(1));
    json_append_member(root, "method", json_mkstring("job.result_manifest"));
    json_append_member(root, "job_id", json_mkstring(job_id));
    if (getenv("XTATE_CONTROL_TOKEN") && getenv("XTATE_CONTROL_TOKEN")[0])
        json_append_member(root, "token", json_mkstring(getenv("XTATE_CONTROL_TOKEN")));
    request = json_stringify(root, NULL);
    json_delete(root);
    if (!request) return NULL;
    if (control_client_request(endpoint, request, response, sizeof(response)) < 0) {
        free(request);
        return NULL;
    }
    free(request);
    root = json_decode(response);
    if (root) {
        JsonNode *result = json_find_member(root, "result");
        JsonNode *rp = result && result->tag == JSON_OBJECT
            ? json_find_member(result, "result_path") : NULL;
        if (rp && rp->tag == JSON_STRING && rp->string_)
            path = dup_str(rp->string_);
        json_delete(root);
    }
    return path;
}

char *result_records_json(const char *endpoint, const char *job_id,
                          int offset, int limit, int *status) {
    char *path;
    FILE *fp;
    JsonNode *root = NULL;
    JsonNode *records = NULL;
    char buffer[8193];
    char *text = NULL;
    int seen = 0, emitted = 0;

    if (status) *status = 500;
    if (!valid_job_id(job_id)) {
        if (status) *status = 400;
        return NULL;
    }
    if (offset < 0) offset = 0;
    if (limit < 1) limit = 1;
    if (limit > 200) limit = 200;
    path = job_result_path(endpoint, job_id);
    if (!path) {
        if (status) *status = 404;
        return NULL;
    }
    fp = file_open_utf8(path);
    free(path);
    if (!fp) {
        if (status) *status = 404;
        return NULL;
    }
    root = json_mkobject();
    records = json_mkarray();
    if (!root || !records) {
        json_delete(root);
        json_delete(records);
        fclose(fp);
        return NULL;
    }
    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        int complete = len > 0 && buffer[len - 1] == '\n';
        while (!complete && !feof(fp)) {
            if (!fgets(buffer, sizeof(buffer), fp)) break;
            len = strlen(buffer);
            complete = len > 0 && buffer[len - 1] == '\n';
        }
        while (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r'))
            buffer[--len] = 0;
        if (len == 0) continue;
        {
            JsonNode *rec = json_decode(buffer);
            if (!rec) continue;
            if (seen < offset) {
                json_delete(rec);
                seen++;
                continue;
            }
            if (emitted >= limit) {
                json_delete(rec);
                break;
            }
            json_append_element(records, rec);
            seen++;
            emitted++;
        }
    }
    fclose(fp);
    json_append_member(root, "records", records);
    json_append_member(root, "offset", json_mknumber(offset));
    json_append_member(root, "limit", json_mknumber(limit));
    json_append_member(root, "next_offset", json_mknumber(offset + emitted));
    json_append_member(root, "count", json_mknumber(emitted));
    text = json_stringify(root, NULL);
    json_delete(root);
    if (text && status) *status = 200;
    return text;
}
