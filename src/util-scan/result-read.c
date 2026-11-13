#include "result-read.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto/crypto-json.h"
#include "../util-data/file-open.h"
#include "control-client.h"

#ifndef NOT_FOUND_ZSTD
#include <zstd.h>
#endif

#define RESULT_READ_MAX_BLOB (64u * 1024u * 1024u)

typedef struct {
    JsonNode *records;
    int offset;
    int limit;
    int seen;
    int emitted;
} RecordSink;

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

static int job_result_paths(const char *endpoint, const char *job_id,
                            char **result_path, char **manifest_path) {
    JsonNode *root = json_mkobject();
    char *request = NULL;
    char response[65536];
    int rc = -1;

    *result_path = NULL;
    *manifest_path = NULL;
    if (!root) return -1;
    json_append_member(root, "id", json_mknumber(1));
    json_append_member(root, "method", json_mkstring("job.result_manifest"));
    json_append_member(root, "job_id", json_mkstring(job_id));
    if (getenv("XTATE_CONTROL_TOKEN") && getenv("XTATE_CONTROL_TOKEN")[0])
        json_append_member(root, "token", json_mkstring(getenv("XTATE_CONTROL_TOKEN")));
    request = json_stringify(root, NULL);
    json_delete(root);
    if (!request) return -1;
    if (control_client_request(endpoint, request, response, sizeof(response)) < 0) {
        free(request);
        return -1;
    }
    free(request);
    root = json_decode(response);
    if (root) {
        JsonNode *result = json_find_member(root, "result");
        JsonNode *rp = result && result->tag == JSON_OBJECT
            ? json_find_member(result, "result_path") : NULL;
        JsonNode *mp = result && result->tag == JSON_OBJECT
            ? json_find_member(result, "manifest_path") : NULL;
        if (rp && rp->tag == JSON_STRING && rp->string_)
            *result_path = dup_str(rp->string_);
        if (mp && mp->tag == JSON_STRING && mp->string_)
            *manifest_path = dup_str(mp->string_);
        json_delete(root);
        rc = (*result_path || *manifest_path) ? 0 : -1;
    }
    return rc;
}

static int append_blob(char *buf, size_t len, RecordSink *sink) {
    size_t pos = 0;
    while (pos < len) {
        char *line = buf + pos;
        char *nl = (char *)memchr(line, '\n', len - pos);
        size_t n = nl ? (size_t)(nl - line) : len - pos;
        char *end;
        while (n > 0 && line[n - 1] == '\r') n--;
        end = line + n;
        *end = 0;
        if (n > 0) {
            JsonNode *rec = json_decode(line);
            if (rec) {
                if (sink->seen < sink->offset) {
                    json_delete(rec);
                    sink->seen++;
                } else if (sink->emitted < sink->limit) {
                    json_append_element(sink->records, rec);
                    sink->seen++;
                    sink->emitted++;
                } else {
                    json_delete(rec);
                    return 0;
                }
            }
        }
        if (!nl) break;
        pos = (size_t)(nl - buf) + 1;
    }
    return 0;
}

static int append_stream(FILE *fp, RecordSink *sink) {
    char buffer[8193];
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
            if (sink->seen < sink->offset) {
                json_delete(rec);
                sink->seen++;
            } else if (sink->emitted < sink->limit) {
                json_append_element(sink->records, rec);
                sink->seen++;
                sink->emitted++;
            } else {
                json_delete(rec);
                break;
            }
        }
    }
    return 0;
}

static int append_chunk(const char *path, int zstd, RecordSink *sink) {
    FILE *fp;
    long n;
    char *blob = NULL;
    size_t blob_len = 0;

    if (!path || !path[0]) return -1;
    if (!zstd) {
        fp = file_open_utf8(path);
        if (!fp) return -1;
        append_stream(fp, sink);
        fclose(fp);
        return 0;
    }
#ifndef NOT_FOUND_ZSTD
    fp = file_open_utf8_mode(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    n = ftell(fp);
    if (n <= 0 || (unsigned long)n > RESULT_READ_MAX_BLOB) { fclose(fp); return -1; }
    rewind(fp);
    blob = (char *)malloc((size_t)n);
    if (!blob) { fclose(fp); return -1; }
    if (fread(blob, 1, (size_t)n, fp) != (size_t)n) {
        fclose(fp); free(blob); return -1;
    }
    fclose(fp);
    {
        unsigned long long dsize = ZSTD_getFrameContentSize(blob, (size_t)n);
        char *plain;
        size_t got;
        if (dsize == ZSTD_CONTENTSIZE_ERROR || dsize == ZSTD_CONTENTSIZE_UNKNOWN ||
            dsize > RESULT_READ_MAX_BLOB) {
            free(blob);
            return -1;
        }
        plain = (char *)malloc((size_t)dsize + 1);
        if (!plain) { free(blob); return -1; }
        got = ZSTD_decompress(plain, (size_t)dsize, blob, (size_t)n);
        free(blob);
        if (ZSTD_isError(got)) { free(plain); return -1; }
        plain[got] = 0;
        append_blob(plain, got, sink);
        free(plain);
        return 0;
    }
#else
    (void)path;
    (void)sink;
    (void)n;
    (void)blob;
    (void)blob_len;
    return -1;
#endif
}

static int append_manifest(const char *manifest_path, RecordSink *sink) {
    FILE *fp;
    long n;
    char *text;
    JsonNode *root;
    JsonNode *chunks;
    JsonNode *comp;
    int zstd = 0;
    int rc = -1;

    fp = file_open_utf8(manifest_path);
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    n = ftell(fp);
    if (n < 0 || (unsigned long)n > RESULT_READ_MAX_BLOB) { fclose(fp); return -1; }
    rewind(fp);
    text = (char *)malloc((size_t)n + 1);
    if (!text) { fclose(fp); return -1; }
    if (fread(text, 1, (size_t)n, fp) != (size_t)n) {
        fclose(fp); free(text); return -1;
    }
    fclose(fp);
    text[n] = 0;
    root = json_decode(text);
    free(text);
    if (!root) return -1;
    comp = json_find_member(root, "compression");
    if (comp && comp->tag == JSON_STRING && comp->string_ &&
        strcmp(comp->string_, "zstd") == 0)
        zstd = 1;
    chunks = json_find_member(root, "chunks");
    if (chunks && chunks->tag == JSON_ARRAY) {
        JsonNode *chunk;
        rc = 0;
        json_foreach(chunk, chunks) {
            JsonNode *path = chunk->tag == JSON_OBJECT
                ? json_find_member(chunk, "path") : NULL;
            if (path && path->tag == JSON_STRING && path->string_) {
                if (append_chunk(path->string_, zstd, sink) != 0) {
                    rc = -1;
                    break;
                }
            }
        }
    }
    json_delete(root);
    return rc;
}

char *result_records_json(const char *endpoint, const char *job_id,
                          int offset, int limit, int *status) {
    char *result_path = NULL, *manifest_path = NULL;
    JsonNode *root = NULL;
    JsonNode *records = NULL;
    RecordSink sink;
    char *text = NULL;
    FILE *fp = NULL;
    int used = 0;

    if (status) *status = 500;
    if (!valid_job_id(job_id)) {
        if (status) *status = 400;
        return NULL;
    }
    if (offset < 0) offset = 0;
    if (limit < 1) limit = 1;
    if (limit > 200) limit = 200;
    if (job_result_paths(endpoint, job_id, &result_path, &manifest_path) != 0) {
        if (status) *status = 404;
        return NULL;
    }

    root = json_mkobject();
    records = json_mkarray();
    if (!root || !records) {
        json_delete(root);
        json_delete(records);
        free(result_path);
        free(manifest_path);
        return NULL;
    }
    sink.records = records;
    sink.offset = offset;
    sink.limit = limit;
    sink.seen = 0;
    sink.emitted = 0;

    if (result_path) {
        fp = file_open_utf8(result_path);
        if (fp) {
            append_stream(fp, &sink);
            fclose(fp);
            used = 1;
        }
    }
    if (!used && manifest_path) {
        if (append_manifest(manifest_path, &sink) == 0) used = 1;
    }
    free(result_path);
    free(manifest_path);
    if (!used) {
        json_delete(root);
        json_delete(records);
        if (status) *status = 404;
        return NULL;
    }

    json_append_member(root, "records", records);
    json_append_member(root, "offset", json_mknumber(offset));
    json_append_member(root, "limit", json_mknumber(limit));
    json_append_member(root, "next_offset", json_mknumber(offset + sink.emitted));
    json_append_member(root, "count", json_mknumber(sink.emitted));
    text = json_stringify(root, NULL);
    json_delete(root);
    if (text && status) *status = 200;
    return text;
}
