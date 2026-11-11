#include "result-store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int result_store_build(const char *result_path, uint64_t chunk_bytes,
                       bool build_index) {
    if (!result_path || chunk_bytes == 0) return 0;
    FILE *in = fopen(result_path, "rb");
    if (!in) return -1;
    char manifest[1200], index[1200];
    snprintf(manifest, sizeof(manifest), "%s.manifest.json", result_path);
    snprintf(index, sizeof(index), "%s.index.json", result_path);
    FILE *mf = fopen(manifest, "w");
    FILE *ix = build_index ? fopen(index, "w") : NULL;
    if (!mf) { fclose(in); return -1; }
    fprintf(mf, "{\"format\":\"ndjson\",\"compression\":\"none\","
                "\"chunks\":[");
    if (ix) fprintf(ix, "{\"chunks\":[");
    char line[65536];
    uint64_t cid = 0, total = 0, records = 0;
    FILE *out = NULL;
    uint64_t cbytes = 0, crecords = 0;
    char cpath[1200] = {0};
    int first = 1;
    while (fgets(line, sizeof(line), in)) {
        size_t n = strlen(line);
        if (!out || (cbytes && cbytes + n > chunk_bytes)) {
            if (out) {
                fclose(out);
                if (ix) fprintf(ix, "%s{\"id\":%llu,\"path\":\"%s\","
                                    "\"bytes\":%llu,\"records\":%llu}",
                                first ? "" : ",", (unsigned long long)cid, cpath,
                                (unsigned long long)cbytes,
                                (unsigned long long)crecords);
                first = 0;
            }
            cid++; cbytes = 0; crecords = 0;
            snprintf(cpath, sizeof(cpath), "%s.%05llu.ndjson", result_path,
                     (unsigned long long)cid);
            out = fopen(cpath, "wb");
            if (!out) break;
        }
        fwrite(line, 1, n, out); cbytes += n; crecords++;
        total += n; records++;
    }
    if (out) {
        fclose(out);
        if (ix) fprintf(ix, "%s{\"id\":%llu,\"path\":\"%s\","
                            "\"bytes\":%llu,\"records\":%llu}",
                        first ? "" : ",", (unsigned long long)cid, cpath,
                        (unsigned long long)cbytes, (unsigned long long)crecords);
        fprintf(mf, "{\"id\":%llu,\"path\":\"%s\",\"bytes\":%llu,"
                    "\"records\":%llu}",
                (unsigned long long)cid, cpath, (unsigned long long)cbytes,
                (unsigned long long)crecords);
    }
    fclose(in);
    fprintf(mf, "],\"total_bytes\":%llu,\"total_records\":%llu}",
            (unsigned long long)total, (unsigned long long)records);
    fclose(mf);
    if (ix) { fprintf(ix, "]}"); fclose(ix); }
    return 0;
}
