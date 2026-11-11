#include "util-scan/job-manager.h"
#include <stdio.h>
int main(void) {
    JobManager *m = job_manager_create(1);
    char *a[] = {"/bin/sleep", "5", NULL};
    Job *j = job_start(m, a, "/tmp/stall-out", "/tmp/stall-log", 0);
    if (!j) return 1;
    job_set_stall_timeout(j, 1);
    if (!job_wait(j, 3000)) return 2;
    printf("stall state=%s\n", job_state_string(job_state(j)));
    return job_state(j) == JOB_STALLED ? 0 : 3;
}
