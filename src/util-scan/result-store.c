#include "result-store.h"
#include "../util-data/file-open.h"
#include "../util-data/json-escape.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../util-out/logger.h"

static void json_file_sink(void *ctx, const char *data, size_t len) {
    fwrite(data, 1, len, (FILE *)ctx);
}

static void fput_json_path(FILE *f, const char *path) {
    fputc('"', f);
    json_escape_to(json_file_sink, f, (const unsigned char *)path, strlen(path));
    fputc('"', f);
}
#ifndef NOT_FOUND_ZSTD
#include <zstd.h>
#endif

#ifndef NOT_FOUND_ZSTD
static int compress_file(const char *path, uint64_t *size) {
    FILE *in = file_open_utf8_mode(path, "rb");
    if (!in) return -1;
    fseek(in, 0, SEEK_END); long n = ftell(in); rewind(in);
    if (n <= 0) { fclose(in); return -1; }
    void *src = malloc((size_t)n);
    if (!src || fread(src, 1, (size_t)n, in) != (size_t)n) { fclose(in); free(src); return -1; }
    fclose(in);
    size_t bound = ZSTD_compressBound((size_t)n);
    void *dst = malloc(bound);
    if (!dst) { free(src); return -1; }
    size_t c = ZSTD_compress(dst, bound, src, (size_t)n, 3);
    free(src);
    if (ZSTD_isError(c)) { free(dst); return -1; }
    char zp[1200]; snprintf(zp, sizeof(zp), "%s.zst", path);
    FILE *out = file_open_utf8_mode(zp, "wb");
    if (!out) { free(dst); return -1; }
    fwrite(dst, 1, c, out); fclose(out); free(dst);
    remove(path);
    snprintf((char *)path, 1200, "%s", zp);
    *size = c;
    return 0;
}
#endif

bool result_store_zstd_available(void) {
#ifdef NOT_FOUND_ZSTD
    return false;
#else
    return true;
#endif
}

int result_store_build(const char *result_path, uint64_t chunk_bytes,
                       bool build_index, const char *compression) {
    if (!result_path || chunk_bytes == 0) return 0;
    bool use_zstd = compression && strcmp(compression, "zstd") == 0;
    if (use_zstd && !result_store_zstd_available()) {
        LOG(LEVEL_WARN, "zstd is not built; writing uncompressed chunks\n");
        use_zstd = false;
    }
    FILE *in = file_open_utf8_mode(result_path, "rb");
    if (!in) return -1;
    char manifest[1200], index[1200];
    snprintf(manifest, sizeof(manifest), "%s.manifest.json", result_path);
    snprintf(index, sizeof(index), "%s.index.json", result_path);
    FILE *mf = file_open_utf8_mode(manifest, "w");
    FILE *ix = build_index ? file_open_utf8_mode(index, "w") : NULL;
    if (!mf) { fclose(in); return -1; }
    fprintf(mf, "{\"format\":\"ndjson\",\"compression\":\"%s\","
                "\"chunks\":[", use_zstd ? "zstd" : "none");
    if (ix) fprintf(ix, "{\"chunks\":[");
    char line[65536];
    uint64_t cid = 0, total = 0, records = 0;
    FILE *out = NULL;
    uint64_t cbytes = 0, crecords = 0;
    char cpath[1200] = {0};
    int first = 1;
    bool chunk_written = false;
    while (fgets(line, sizeof(line), in)) {
        size_t n = strlen(line);
        if (!out || (cbytes && cbytes + n > chunk_bytes)) {
            if (out) {
                fclose(out);
#ifndef NOT_FOUND_ZSTD
                if (use_zstd)
                    compress_file(cpath, &cbytes);
#endif
                fprintf(mf, "%s{\"id\":%llu,\"path\":",
                        first ? "" : ",", (unsigned long long)cid);
                fput_json_path(mf, cpath);
                fprintf(mf, ",\"bytes\":%llu,\"records\":%llu}",
                        (unsigned long long)cbytes,
                        (unsigned long long)crecords);
                if (ix) {
                    fprintf(ix, "%s{\"id\":%llu,\"path\":",
                            first ? "" : ",", (unsigned long long)cid);
                    fput_json_path(ix, cpath);
                    fprintf(ix, ",\"bytes\":%llu,\"records\":%llu}",
                            (unsigned long long)cbytes,
                            (unsigned long long)crecords);
                }
                first = 0;
            }
            cid++; cbytes = 0; crecords = 0;
            snprintf(cpath, sizeof(cpath), "%s.%05llu.ndjson", result_path,
                     (unsigned long long)cid);
            out = file_open_utf8_mode(cpath, "wb");
            if (!out) break;
        }
        fwrite(line, 1, n, out); cbytes += n; crecords++; chunk_written = true;
        total += n; records++;
    }
    if (out) {
        fclose(out);
#ifndef NOT_FOUND_ZSTD
            if (use_zstd)
                compress_file(cpath, &cbytes);
#endif
            if (ix) {
                fprintf(ix, "%s{\"id\":%llu,\"path\":",
                        first ? "" : ",", (unsigned long long)cid);
                fput_json_path(ix, cpath);
                fprintf(ix, ",\"bytes\":%llu,\"records\":%llu}",
                        (unsigned long long)cbytes, (unsigned long long)crecords);
            }
        fprintf(mf, "%s{\"id\":%llu,\"path\":",
                first ? "" : ",", (unsigned long long)cid);
        fput_json_path(mf, cpath);
        fprintf(mf, ",\"bytes\":%llu,\"records\":%llu}",
                (unsigned long long)cbytes, (unsigned long long)crecords);
    }
    fclose(in);
    fprintf(mf, "],\"total_bytes\":%llu,\"total_records\":%llu}",
            (unsigned long long)total, (unsigned long long)records);
    fclose(mf);
    if (ix) { fprintf(ix, "]}"); fclose(ix); }
    if (chunk_written) remove(result_path);
    return 0;
}
