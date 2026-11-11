#include "util-scan/job-manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    JobManager *m = job_manager_create(2);
    char *a1[] = {"/bin/sleep", "5", NULL};
    Job *j = job_start(m, a1, "/tmp/job-result", "/tmp/job-log", 1);
    if (!j) return 1;
    if (!job_wait(j, 4000)) return 2;
    printf("timeout state=%s exit=%u\n", job_state_string(job_state(j)), job_exit_code(j));
    if (job_state(j) != JOB_TIMED_OUT) return 3;

    char *a2[] = {"/bin/sleep", "5", NULL};
    Job *k = job_start(m, a2, "/tmp/job-result2", "/tmp/job-log2", 0);
    if (!k) return 4;
    usleep(200000);
    if (!job_cancel(k)) return 5;
    if (!job_wait(k, 2000)) return 6;
    printf("cancel state=%s\n", job_state_string(job_state(k)));
    if (job_state(k) != JOB_CANCELLED) return 7;

    char *a3[] = {"/bin/true", NULL};
    Job *t = job_start(m, a3, "/tmp/job-result3", "/tmp/job-log3", 0);
    if (!job_wait(t, 2000) || job_state(t) != JOB_COMPLETED) return 8;
    printf("complete state=%s exit=%u\n", job_state_string(job_state(t)), job_exit_code(t));
    job_manager_destroy(m);
    return 0;
}
