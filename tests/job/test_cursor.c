#include "util-scan/job-manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    JobManager *m = job_manager_create(1);
    char *a[] = {"/bin/sleep", "2", NULL};
    Job *j = job_start(m, a, "/tmp/cursor-result", "/tmp/cursor-log", 0);
    if (!j) return 1;
    FILE *f = fopen("/tmp/cursor-result", "wb");
    if (!f) return 2;
    fseeko(f, 5LL * 1024 * 1024 * 1024, SEEK_SET);
    fputs("big\n", f);
    fclose(f);
    char buf[64];
    uint64_t next = 0;
    bool trunc = false;
    uint64_t n = job_read_results(j, 5LL * 1024 * 1024 * 1024, buf, sizeof(buf), &next, &trunc);
    printf("n=%llu next=%llu trunc=%d data=%s", (unsigned long long)n,
           (unsigned long long)next, trunc, buf);
    if (n != 4 || strcmp(buf, "big\n") != 0) return 3;
    job_cancel(j); job_wait(j, 1000); job_manager_destroy(m);
    return 0;
}

