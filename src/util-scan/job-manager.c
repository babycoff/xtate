#include "job-manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#include <unistd.h>
#endif

struct Job {
    char      id[32];
    JobState  state;
    unsigned  timeout_sec;
    unsigned  stall_timeout_sec;
    unsigned  heartbeat_timeout_sec;
    long long last_progress_ms;
    long long last_heartbeat_ms;
    long long last_size;
    unsigned long long last_sent;
    unsigned long long last_targets;
    char     *heartbeat_path;
    uint64_t  result_chunk_bytes;
    uint64_t  result_quota_bytes;
    char     *result_compression;
    bool      result_index;
    bool      result_finalized;
    unsigned  exit_code;
    long long start_ms;
    long long end_ms;
    bool      cancel_requested;
    char     *result_path;
    char     *log_path;
    Job      *next;
#ifdef _WIN32
    PROCESS_INFORMATION pi;
    HANDLE              job_object;
#else
    pid_t pid;
#endif
};

struct JobManager {
    Job     *head;
    unsigned max_jobs;
    unsigned max_retained;
    unsigned ttl_sec;
    unsigned seq;
#ifdef _WIN32
    CRITICAL_SECTION mutex;
#else
    pthread_mutex_t mutex;
#endif
};

static char *dupstr(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

const char *job_state_string(JobState s) {
    switch (s) {
        case JOB_QUEUED: return "queued";
        case JOB_RUNNING: return "running";
        case JOB_COMPLETED: return "completed";
        case JOB_FAILED: return "failed";
        case JOB_CANCELLED: return "cancelled";
        case JOB_TIMED_OUT: return "timed_out";
        case JOB_STALLED: return "stalled";
        default: return "unknown";
    }
}

bool job_is_terminal(const Job *job) {
    return job && (job->state == JOB_COMPLETED || job->state == JOB_FAILED ||
                   job->state == JOB_CANCELLED || job->state == JOB_TIMED_OUT ||
                   job->state == JOB_STALLED);
}

void job_set_stall_timeout(Job *job, unsigned seconds) {
    if (job) job->stall_timeout_sec = seconds;
}

void job_set_result_config(Job *job, uint64_t chunk_bytes, bool index,
                           const char *compression, uint64_t quota_bytes) {
    if (!job) return;
    free(job->result_compression);
    job->result_chunk_bytes = chunk_bytes;
    job->result_index = index;
    job->result_quota_bytes = quota_bytes;
    job->result_compression = compression ? dupstr(compression) : NULL;
}
uint64_t job_result_chunk_bytes(const Job *job) { return job ? job->result_chunk_bytes : 0; }
bool job_result_index_enabled(const Job *job) { return job ? job->result_index : false; }
const char *job_result_compression(const Job *job) { return job ? job->result_compression : NULL; }
uint64_t job_result_quota(const Job *job) { return job ? job->result_quota_bytes : 0; }
bool job_result_finalized(const Job *job) { return job ? job->result_finalized : false; }
void job_mark_result_finalized(Job *job) { if (job) job->result_finalized = true; }

void job_set_heartbeat(Job *job, const char *path, unsigned timeout_sec) {
    if (!job) return;
    free(job->heartbeat_path);
    job->heartbeat_path = path ? dupstr(path) : NULL;
    job->heartbeat_timeout_sec = timeout_sec;
}

static long long now_ms(void) {
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

JobManager *job_manager_create(unsigned max_jobs) {
    JobManager *m = calloc(1, sizeof(*m));
    if (m) {
        m->max_jobs = max_jobs ? max_jobs : 4;
        m->max_retained = 100;
        m->ttl_sec = 86400;
#ifdef _WIN32
        InitializeCriticalSection(&m->mutex);
#else
        pthread_mutex_init(&m->mutex, NULL);
#endif
    }
    return m;
}

static void close_handles(Job *j) {
#ifdef _WIN32
    if (j->pi.hProcess) CloseHandle(j->pi.hProcess);
    if (j->pi.hThread) CloseHandle(j->pi.hThread);
    if (j->job_object) CloseHandle(j->job_object);
#else
    (void)j;
#endif
}

static void job_free(Job *j) {
    if (!j) return;
    close_handles(j);
    free(j->result_path);
    free(j->log_path);
    free(j->heartbeat_path);
    free(j->result_compression);
    free(j);
}

void job_manager_lock(JobManager *m) {
    if (!m) return;
#ifdef _WIN32
    EnterCriticalSection(&m->mutex);
#else
    pthread_mutex_lock(&m->mutex);
#endif
}
void job_manager_unlock(JobManager *m) {
    if (!m) return;
#ifdef _WIN32
    LeaveCriticalSection(&m->mutex);
#else
    pthread_mutex_unlock(&m->mutex);
#endif
}

static bool read_heartbeat(Job *j, long long *sent, long long *targets,
                           long long *stamp, char *phase, size_t phase_len);

bool job_heartbeat_info(Job *job, char *phase, size_t phase_cap,
                        uint64_t *sent, uint64_t *targets,
                        uint64_t *age_ms) {
    long long s = 0, t = 0, stamp = 0;
    char ph[32] = "unknown";
    if (!read_heartbeat(job, &s, &t, &stamp, ph, sizeof(ph))) return false;
    if (phase && phase_cap) snprintf(phase, phase_cap, "%s", ph);
    if (sent) *sent = (uint64_t)s;
    if (targets) *targets = (uint64_t)t;
    if (age_ms) *age_ms = stamp ? (uint64_t)((long long)time(NULL) - stamp) * 1000 : 0;
    return true;
}

uint64_t job_result_bytes(Job *job) {
    if (!job || !job->result_path) return 0;
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (GetFileAttributesExA(job->result_path, GetFileExInfoStandard, &fa))
        return ((uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
#else
    struct stat st;
    if (stat(job->result_path, &st) == 0) return (uint64_t)st.st_size;
#endif
    return 0;
}

uint64_t job_read_results(Job *job, uint64_t offset, char *buf, size_t cap,
                          uint64_t *next_offset, bool *truncated) {
    if (next_offset) *next_offset = offset;
    if (truncated) *truncated = false;
    if (!job || !job->result_path || !buf || cap == 0) return 0;
    FILE *fp = fopen(job->result_path, "rb");
    if (!fp) return 0;
#ifdef _WIN32
    if (_fseeki64(fp, (__int64)offset, SEEK_SET) != 0) { fclose(fp); return 0; }
#else
    if (fseeko(fp, (off_t)offset, SEEK_SET) != 0) { fclose(fp); return 0; }
#endif
    size_t n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = 0;
    /* return complete lines only; leave the tail for the next chunk */
    size_t end = n;
    if (n && buf[n - 1] != '\n') {
        while (end && buf[end - 1] != '\n') end--;
        if (end == 0) {
            if (truncated) *truncated = true;
            return 0;
        }
    }
    buf[end] = 0;
    if (next_offset) *next_offset = offset + end;
    if (truncated && end < n) *truncated = true;
    return end;
}

void job_manager_set_retention(JobManager *m, unsigned max_jobs,
                               unsigned ttl_sec) {
    if (!m) return;
    m->max_retained = max_jobs ? max_jobs : 1;
    m->ttl_sec = ttl_sec;
}

void job_manager_prune(JobManager *m) {
    if (!m) return;
    unsigned terminal = 0;
    for (Job *j = m->head; j; j = j->next)
        if (job_is_terminal(j)) terminal++;
    long long now = now_ms();
    Job **pp = &m->head;
    while (*pp) {
        Job *j = *pp;
        bool old = m->ttl_sec && job_is_terminal(j) && j->end_ms > 0 &&
                   now - j->end_ms >= (long long)m->ttl_sec * 1000;
        if (old || terminal > m->max_retained) {
            *pp = j->next;
            if (job_is_terminal(j)) terminal--;
            job_free(j);
            continue;
        }
        pp = &j->next;
    }
}

void job_manager_destroy(JobManager *m) {
    if (!m) return;
    Job *j = m->head;
    while (j) {
        Job *next = j->next;
        if (!job_is_terminal(j)) job_cancel(j);
        job_free(j);
        j = next;
    }
#ifdef _WIN32
    DeleteCriticalSection(&m->mutex);
#else
    pthread_mutex_destroy(&m->mutex);
#endif
    free(m);
}

unsigned job_count(JobManager *m) {
    unsigned n = 0;
    for (Job *j = m ? m->head : NULL; j; j = j->next) n++;
    return n;
}

Job *job_first(JobManager *m) { return m ? m->head : NULL; }
Job *job_next(Job *j) { return j ? j->next : NULL; }

Job *job_find(JobManager *m, const char *id) {
    for (Job *j = m ? m->head : NULL; j; j = j->next)
        if (id && strcmp(j->id, id) == 0) return j;
    return NULL;
}

const char *job_id(const Job *j) { return j ? j->id : ""; }
JobState job_state(const Job *j) { return j ? j->state : JOB_FAILED; }
const char *job_result_path(const Job *j) { return j ? j->result_path : NULL; }
const char *job_log_path(const Job *j) { return j ? j->log_path : NULL; }
unsigned job_exit_code(const Job *j) { return j ? j->exit_code : 0; }
unsigned job_elapsed_ms(const Job *j) {
    if (!j || j->start_ms == 0) return 0;
    long long end = j->end_ms ? j->end_ms
                              : (job_is_terminal(j) ? j->start_ms : now_ms());
    if (end < j->start_ms) return 0;
    return (unsigned)(end - j->start_ms);
}

#ifdef _WIN32
static HANDLE create_file_utf8(const char *path, DWORD access, DWORD share,
                               DWORD creation, DWORD flags) {
    if (!path || !path[0]) return INVALID_HANDLE_VALUE;
    wchar_t wpath[2048];
    int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                                (int)(sizeof(wpath) / sizeof(wpath[0])));
    if (n <= 0) return INVALID_HANDLE_VALUE;
    return CreateFileW(wpath, access, share, NULL, creation, flags, NULL);
}
#endif
static Job *new_job(JobManager *m, const char *result_path,
                    const char *log_path, unsigned timeout_sec) {
    Job *j = calloc(1, sizeof(*j));
    if (!j) return NULL;
    snprintf(j->id, sizeof(j->id), "job-%u", ++m->seq);
    j->state = JOB_QUEUED;
    j->start_ms = now_ms();
    j->last_progress_ms = j->start_ms;
    j->last_heartbeat_ms = j->start_ms;
    j->timeout_sec = timeout_sec;
    j->heartbeat_timeout_sec = 30;
    j->result_path = result_path ? dupstr(result_path) : NULL;
    j->log_path = log_path ? dupstr(log_path) : NULL;
    if (result_path) {
        size_t n = strlen(result_path) + 16;
        j->heartbeat_path = malloc(n);
        if (j->heartbeat_path)
            snprintf(j->heartbeat_path, n, "%s.heartbeat", result_path);
    }
    j->next = m->head;
    m->head = j;
    return j;
}

#ifdef _WIN32
static void append_quoted(char **buf, size_t *len, size_t *cap, const char *s) {
    size_t need = strlen(s) * 2 + 4;
    if (*len + need > *cap) {
        *cap = (*cap + need) * 2;
        *buf = realloc(*buf, *cap);
    }
    (*buf)[(*len)++] = '"';
    for (; *s; s++) {
        if (*s == '"') (*buf)[(*len)++] = '\\';
        (*buf)[(*len)++] = *s;
    }
    (*buf)[(*len)++] = '"';
    (*buf)[*len] = 0;
}

Job *job_start(JobManager *m, char *const argv[], const char *result_path,
               const char *log_path, unsigned timeout_sec) {
    if (!m || !argv || !argv[0]) return NULL;
    unsigned active = 0;
    for (Job *j = m->head; j; j = j->next)
        if (!job_is_terminal(j)) active++;
    if (active >= m->max_jobs) return NULL;

    Job *j = new_job(m, result_path, log_path, timeout_sec);
    if (!j) return NULL;

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE out = create_file_utf8(result_path, GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    HANDLE err = create_file_utf8(log_path, GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    (void)sa;
    if (out == INVALID_HANDLE_VALUE) {
        out = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (err == INVALID_HANDLE_VALUE) {
        err = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (out == INVALID_HANDLE_VALUE || err == INVALID_HANDLE_VALUE) {
        if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
        if (err != INVALID_HANDLE_VALUE) CloseHandle(err);
        j->state = JOB_FAILED;
        j->exit_code = 1;
        return j;
    }

    size_t cap = 256, len = 0;
    char *cmd = calloc(cap, 1);
    for (int i = 0; argv[i]; i++) {
        if (i) cmd[len++] = ' ';
        append_quoted(&cmd, &len, &cap, argv[i]);
    }

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out;
    si.hStdError = err;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    j->job_object = CreateJobObjectA(NULL, NULL);
    if (j->job_object) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;
        ZeroMemory(&li, sizeof(li));
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(j->job_object, JobObjectExtendedLimitInformation,
                                &li, sizeof(li));
    }

    wchar_t wcmd[8192];
    int cn = MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd,
                        (int)(sizeof(wcmd) / sizeof(wcmd[0])));
    BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, NULL,
                             NULL, &si, &j->pi);
    if (!ok) fprintf(stderr, "CreateProcessW failed cn=%d gle=%lu cmd=%s\n",
                     cn, (unsigned long)GetLastError(), cmd);
    CloseHandle(out); CloseHandle(err); free(cmd);
    if (!ok) {
        j->state = JOB_FAILED;
        j->exit_code = 1;
        return j;
    }
    if (j->job_object)
        AssignProcessToJobObject(j->job_object, j->pi.hProcess);
    j->state = JOB_RUNNING;
    j->start_ms = now_ms();
    j->last_progress_ms = j->start_ms;
    j->last_heartbeat_ms = j->start_ms;
    j->last_progress_ms = j->start_ms;
    return j;
}
#else
Job *job_start(JobManager *m, char *const argv[], const char *result_path,
               const char *log_path, unsigned timeout_sec) {
    if (!m || !argv || !argv[0]) return NULL;
    unsigned active = 0;
    for (Job *j = m->head; j; j = j->next)
        if (!job_is_terminal(j)) active++;
    if (active >= m->max_jobs) return NULL;

    Job *j = new_job(m, result_path, log_path, timeout_sec);
    if (!j) return NULL;
    int out = open(result_path ? result_path : "/dev/null",
                   O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int err = open(log_path ? log_path : "/dev/null",
                   O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0 || err < 0) {
        if (out >= 0) close(out);
        if (err >= 0) close(err);
        j->state = JOB_FAILED;
        j->exit_code = 1;
        return j;
    }
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        dup2(out, STDOUT_FILENO);
        dup2(err, STDERR_FILENO);
        close(out); close(err);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(out); close(err);
    if (pid < 0) {
        j->state = JOB_FAILED;
        j->exit_code = 1;
        return j;
    }
    j->pid = pid;
    j->state = JOB_RUNNING;
    j->start_ms = now_ms();
    j->last_progress_ms = j->start_ms;
    j->last_heartbeat_ms = j->start_ms;
    j->last_progress_ms = j->start_ms;
    return j;
}
#endif

static void terminate_job(Job *j) {
#ifdef _WIN32
    if (j->job_object) TerminateJobObject(j->job_object, 1);
    else if (j->pi.hProcess) TerminateProcess(j->pi.hProcess, 1);
#else
    if (j->pid > 0) kill(-j->pid, SIGTERM);
#endif
}

static bool read_heartbeat(Job *j, long long *sent, long long *targets,
                           long long *stamp, char *phase, size_t phase_len) {
    if (!j->heartbeat_path) return false;
    FILE *fp = fopen(j->heartbeat_path, "r");
    if (!fp) return false;
    char line[256];
    *stamp = 0;
    while (fgets(line, sizeof(line), fp)) {
        long long v;
        if (sscanf(line, "sent=%lld", &v) == 1) *sent = v;
        else if (sscanf(line, "targets=%lld", &v) == 1) *targets = v;
        else if (sscanf(line, "time=%lld", &v) == 1) *stamp = v;
        else if (sscanf(line, "phase=%31s", phase) == 1) phase[31] = 0;
    }
    fclose(fp);
    return *stamp > 0;
}

JobState job_poll(Job *j) {
    if (!j || job_is_terminal(j)) return j ? j->state : JOB_FAILED;
    if (j->state != JOB_RUNNING) return j->state;

    /* Reap a finished worker before applying liveness/deadline rules. */
#ifdef _WIN32
    DWORD code = 0;
    if (WaitForSingleObject(j->pi.hProcess, 0) == WAIT_OBJECT_0) {
        GetExitCodeProcess(j->pi.hProcess, &code);
        j->exit_code = code;
        j->end_ms = now_ms();
        j->state = j->cancel_requested ? JOB_CANCELLED
                                       : (code == 0 ? JOB_COMPLETED : JOB_FAILED);
        return j->state;
    }
#else
    int status = 0;
    pid_t r = waitpid(j->pid, &status, WNOHANG);
    if (r == j->pid) {
        if (WIFEXITED(status)) j->exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) j->exit_code = 128 + WTERMSIG(status);
        j->end_ms = now_ms();
        j->state = j->cancel_requested ? JOB_CANCELLED
                                       : (j->exit_code == 0 ? JOB_COMPLETED
                                                            : JOB_FAILED);
        return j->state;
    }
#endif

    long long sent = 0, targets = 0, stamp = 0;
    char phase[32] = "tx";
    bool hb = read_heartbeat(j, &sent, &targets, &stamp, phase, sizeof(phase));
    if (hb && time(NULL) - stamp <= 2) {
        j->last_heartbeat_ms = now_ms();
        if (strcmp(phase, "tx") != 0) {
            j->last_progress_ms = now_ms();
            j->last_sent = (unsigned long long)sent;
            j->last_targets = (unsigned long long)targets;
        } else if (sent != (long long)j->last_sent ||
            targets != (long long)j->last_targets) {
            j->last_sent = (unsigned long long)sent;
            j->last_targets = (unsigned long long)targets;
            j->last_progress_ms = now_ms();
        }
    }
    long long now = now_ms();
    if (!j->cancel_requested && j->heartbeat_timeout_sec &&
        now - j->last_heartbeat_ms >= (long long)j->heartbeat_timeout_sec * 1000) {
        terminate_job(j);
        j->state = JOB_STALLED;
        j->end_ms = now;
        return j->state;
    }
    if (!j->cancel_requested && j->stall_timeout_sec &&
        now - j->last_progress_ms >= (long long)j->stall_timeout_sec * 1000) {
        terminate_job(j);
        j->state = JOB_STALLED;
        j->end_ms = now;
        return j->state;
    }
    if (!j->cancel_requested && j->timeout_sec &&
        job_elapsed_ms(j) >= j->timeout_sec * 1000) {
        terminate_job(j);
        j->state = JOB_TIMED_OUT;
        j->end_ms = now_ms();
        return j->state;
    }
    return j->state;
}

bool job_cancel(Job *j) {
    if (!j || job_is_terminal(j)) return false;
    j->cancel_requested = true;
    terminate_job(j);
    return true;
}

bool job_wait(Job *j, unsigned timeout_ms) {
    long long deadline = now_ms() + timeout_ms;
    while (j && !job_is_terminal(j)) {
        job_poll(j);
        if (job_is_terminal(j)) return true;
        if (now_ms() >= deadline) return false;
#ifdef _WIN32
        Sleep(50);
#else
        struct timespec ts = {0, 50 * 1000000};
        nanosleep(&ts, NULL);
#endif
    }
    return true;
}
