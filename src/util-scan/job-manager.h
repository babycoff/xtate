#ifndef JOB_MANAGER_H
#define JOB_MANAGER_H
#include <stdbool.h>
#include <stddef.h>

typedef enum JobState {
    JOB_QUEUED = 0,
    JOB_RUNNING,
    JOB_COMPLETED,
    JOB_FAILED,
    JOB_CANCELLED,
    JOB_TIMED_OUT,
    JOB_STALLED,
} JobState;

typedef struct Job Job;
typedef struct JobManager JobManager;

/* Control-plane API; safe for one manager thread (MCP/TUI serialize calls). */
JobManager *job_manager_create(unsigned max_jobs);
void        job_manager_destroy(JobManager *m);

/* argv must be NULL-terminated and contain no shell. stdout/stderr are
 * redirected to result_path/log_path when non-NULL. timeout_sec==0 means none. */
Job *job_start(JobManager *m, char *const argv[], const char *result_path,
               const char *log_path, unsigned timeout_sec);
JobState job_poll(Job *job);
bool     job_cancel(Job *job);
void     job_set_stall_timeout(Job *job, unsigned seconds);
void     job_set_heartbeat(Job *job, const char *path, unsigned timeout_sec);
bool     job_wait(Job *job, unsigned timeout_ms);

const char *job_id(const Job *job);
JobState    job_state(const Job *job);
const char *job_state_string(JobState s);
const char *job_result_path(const Job *job);
const char *job_log_path(const Job *job);
unsigned    job_exit_code(const Job *job);
unsigned    job_elapsed_ms(const Job *job);
bool        job_is_terminal(const Job *job);

Job  *job_find(JobManager *m, const char *id);
Job  *job_first(JobManager *m);
Job  *job_next(Job *job);
unsigned job_count(JobManager *m);
#endif
