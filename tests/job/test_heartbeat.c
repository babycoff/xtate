#include "util-scan/job-manager.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void beat(const char *path, unsigned long long n, const char *phase) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "time=%lld\nsent=%llu\ntargets=%llu\nsuccess=0\nfailed=0\ninfo=0\nphase=%s\n",
            (long long)time(NULL), n, n, phase);
    fclose(f);
}

static int run_case(const char *result, const char *phase) {
    JobManager *m = job_manager_create(1);
    char *a[] = {"/bin/sleep", "6", NULL};
    Job *j = job_start(m, a, result, "/tmp/hb-test.log", 0);
    if (!j) return 10;
    char hb[512];
    snprintf(hb, sizeof(hb), "%s.heartbeat", result);
    job_set_stall_timeout(j, 1);
    job_set_heartbeat(j, hb, 2);
    unsigned long long n = 1;
    for (int i = 0; i < 25; i++) {
        beat(hb, n++, phase);
        job_poll(j);
        if (i == 15 && job_state(j) != JOB_RUNNING) {
            printf("unexpected terminal i=%d state=%s\\n", i, job_state_string(job_state(j)));
            job_manager_destroy(m); return 11;
        }
        usleep(100000);
    }
    for (int i = 0; i < 40; i++) {
        job_poll(j);
        if (job_is_terminal(j)) break;
        usleep(100000);
    }
    printf("%s state=%s\\n", phase, job_state_string(job_state(j)));
    int ok = job_state(j) == JOB_STALLED;
    job_manager_destroy(m);
    return ok ? 0 : 12;
}

int main(void) {
    if (run_case("/tmp/hb-live", "tx") != 0) return 1;
    if (run_case("/tmp/hb-drain", "draining") != 0) return 2;
    printf("heartbeat tests: PASS\\n");
    return 0;
}
