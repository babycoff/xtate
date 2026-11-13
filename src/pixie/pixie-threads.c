#include "pixie-threads.h"

#if defined(_WIN32)
#include <Windows.h>
#include <process.h>
#include "../util-misc/misc.h"
#endif

#if defined(__GNUC__) && !defined(_WIN32)
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||       \
    defined(__OpenBSD__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#ifndef UNUSEDPARM
#ifdef _MSC_VER
#define UNUSEDPARM(x) x = (x)
#else
#define UNUSEDPARM(x)
#endif
#endif

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"

/****************************************************************************
 ****************************************************************************/
void pixie_cpu_raise_priority(void) {
#if defined _WIN32
    DWORD_PTR result;
    result = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    if (result == 0) {
        LOG(LEVEL_ERROR, "(set_priority) returned error win32:%u\n",
            (unsigned)GetLastError());
    }
#elif defined(__linux__) && defined(__GNUC__)
    pthread_t      thread = pthread_self();
    pthread_attr_t thAttr;
    int            policy              = 0;
    int            max_prio_for_policy = 0;

    pthread_attr_init(&thAttr);
    pthread_attr_getschedpolicy(&thAttr, &policy);
    max_prio_for_policy = sched_get_priority_max(policy);

    pthread_setschedprio(thread, max_prio_for_policy);
    pthread_attr_destroy(&thAttr);
    return;

#endif
}

/****************************************************************************
 * Set the current thread (implicit) to run exclusively on the explicit
 * process.
 * http://en.wikipedia.org/wiki/Processor_affinity
 ****************************************************************************/
void pixie_cpu_set_affinity(unsigned processor) {
#if defined _WIN32
    DWORD_PTR mask;
    DWORD_PTR result;
    if (processor > 0)
        processor--;
    mask = ((size_t)1) << processor;

    // printf("mask(%u) = 0x%08x\n", processor, mask);
    result = SetThreadAffinityMask(GetCurrentThread(), mask);
    if (result == 0) {
        LOG(LEVEL_ERROR, "(set_affinity) returned error win32:%u\n",
            (unsigned)GetLastError());
    }
#elif defined(__linux__) && defined(__GNUC__) && !defined(__TERMUX__)
    int       x;
    pthread_t thread = pthread_self();
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);

    /*make it be understandable*/
    CPU_SET(processor, &cpuset);

    x = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (x != 0) {
        LOG(LEVEL_ERROR, "(set_affinity) returned error linux:%d\n", errno);
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
    defined(__OpenBSD__)
    /* FIXME: add code here */
    UNUSEDPARM(x);
#endif
}

/****************************************************************************
 ****************************************************************************/
unsigned pixie_cpu_get_count(void) {
#if defined _WIN32
    /* WINDOWS - use GetProcessAffinityMask() function */
    size_t x;
#if defined _M_X64
    DWORD_PTR process_mask = 0;
    DWORD_PTR system_mask  = 0;
#else
    unsigned long process_mask = 0;
    unsigned long system_mask  = 0;
#endif
    unsigned count = 0;
    unsigned i;

    x = GetProcessAffinityMask(GetCurrentProcess(), &process_mask,
                               &system_mask);
    if (x == 0) {
        LOG(LEVEL_ERROR, "GetProcessAffinityMask() returned error %u\n",
            (unsigned)GetLastError());
        return 1;
    }
    for (i = 0; i < 32; i++) {
        if (system_mask & 1)
            count++;
        system_mask >>= 1;
    }
    if (count == 0)
        return 1;
    else
        return count;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
    defined(__OpenBSD__)
    /* BSD - use sysctl() function */
    int    x;
    int    mib[2];
    size_t ncpu_length;
    int    ncpu = 1;

    mib[0]      = CTL_HW;
    mib[1]      = HW_NCPU;
    ncpu_length = sizeof(ncpu);
    x           = sysctl(mib, 2, &ncpu, &ncpu_length, NULL, 0);
    if (x == -1) {
        LOGPERROR("sysctl(HW_NCPU) failed");
        return 1;
    } else
        return (unsigned)ncpu;
#elif defined linux
    /* http://linux.die.net/man/2/sched_getaffinity */
    {
        pid_t     pid;
        cpu_set_t mask;
        int       err;

        /* Gegret our process ID */
        pid = getpid();

        /* Get list of available CPUs for our system */
        err = sched_getaffinity(pid, sizeof(mask), &mask);
        if (err) {
            LOGPERROR("sched_getaffinity");
            return 1;
        } else {
#ifndef CPU_COUNT
            return 1;
#else
            return CPU_COUNT(&mask);
#endif
        }
    }
#elif defined(_SC_NPROCESSORS_ONLN)
    /* Linux, Solaris, Mac OS>=10.4 */
    return sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(_SC_NPROC_ONLN)
    /* Irix */
    return sysconf(_SC_NPROC_ONLN);
#elif defined(MPC_GETNUMSPUS)
    return mpctl(MPC_GETNUMSPUS, 0, 0);
#else
#error need to find CPU count
    /* UNKNOWN - Well, we don't know the type of system which means we won't
     * be able to start multiple threads anyway, so just return '1' */
    return 1;
#endif
}

/****************************************************************************
 ****************************************************************************/
#if defined(_WIN32)
typedef struct PixieThreadStart {
    void (*fn)(void *);
    void *arg;
} PixieThreadStart;

static unsigned __stdcall _pixie_thread_start(void *p) {
    PixieThreadStart start = *(PixieThreadStart *)p;

    free(p);
    start.fn(start.arg);
    return 0;
}
#endif

size_t pixie_begin_thread(void (*worker_thread)(void *), unsigned flags,
                          void *worker_data) {
#if defined(_WIN32)
    size_t            handle;
    PixieThreadStart *start;

    UNUSEDPARM(flags);
    start = malloc(sizeof(*start));
    if (start == NULL) {
        return 0;
    }
    start->fn  = worker_thread;
    start->arg = worker_data;

    /* _beginthread() closes its handle when the thread exits, so a later
     * join would wait on a stale/recycled handle. _beginthreadex() returns a
     * handle that the joiner owns and closes. */
    handle = (size_t)_beginthreadex(NULL, 0, _pixie_thread_start, start, 0,
                                    NULL);
    if (handle == 0) {
        free(start);
        return 0;
    }
    return handle;
#else
    typedef void *(*PTHREADFUNC)(void *);
    pthread_t thread_id = 0;
    pthread_create(&thread_id, NULL, (PTHREADFUNC)worker_thread, worker_data);
    return (size_t)thread_id;
#endif
}

/****************************************************************************
 ****************************************************************************/
void pixie_thread_join(size_t thread_handle) {
    if (thread_handle == 0) {
        return; /* thread creation failed, or the handle is already closed */
    }
#if defined(_WIN32)
    WaitForSingleObject((HANDLE)thread_handle, INFINITE);
    CloseHandle((HANDLE)thread_handle);
#else
    void *p;

    pthread_join((pthread_t)thread_handle, &p);
#endif
}

#if defined(_WIN32)
const DWORD MS_VC_EXCEPTION = 0x406D1388;
#pragma pack(push, 8)
typedef struct tagTHREADNAME_INFO {
    DWORD  dwType;     // Must be 0x1000.
    LPCSTR szName;     // Pointer to name (in user addr space).
    DWORD  dwThreadID; // Thread ID (-1=caller thread).
    DWORD  dwFlags;    // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)
#endif

void pixie_set_thread_name(const char *name) {
#if defined(_WIN32)
    // https://docs.microsoft.com/ru-ru/visualstudio/debugger/how-to-set-a-thread-name-in-native-code
#if defined(__MINGW64__) || defined(__MINGW32__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
    THREADNAME_INFO info;
#if defined(__MINGW64__) || defined(__MINGW32__)
#pragma GCC diagnostic pop
#endif
    DWORD   thread_id;
    HANDLE  h_thread;
    HRESULT hr;
    wchar_t wz_name[128];
    h_thread  = GetCurrentThread();
    thread_id = GetCurrentThreadId();
    swprintf_s(wz_name, ARRAY_SIZE(wz_name), L"%hs", name);
#if defined(__MINGW64__) || defined(__MINGW32__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
#endif
    hr = SetThreadDescription(h_thread, wz_name);
#if defined(__MINGW64__) || defined(__MINGW32__)
#pragma GCC diagnostic pop
#endif
    if (FAILED(hr)) {
        LOG(LEVEL_WARN, "set thread name %" PRIuPTR " %s. Error %ld\n",
            (size_t)thread_id, name, hr);
    }

    info.dwType     = 0x1000;
    info.szName     = name;
    info.dwThreadID = thread_id;
    info.dwFlags    = 0;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 6320 6322)
#endif

#ifdef _MSC_VER
    __try {
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR),
                       (ULONG_PTR *)&info);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#elif defined(__APPLE__)
    int       err;
    pthread_t thread_handle = pthread_self();
    err                     = pthread_setname_np(name);
    if (err != 0) {
        LOG(LEVEL_WARN, "set thread name %" PRIuPTR " %s. Error %d\n",
            thread_handle, name, err);
    }
#else
#if defined(HAVE_PTHREAD_SETNAME_NP) && !defined(XTATE_NO_PTHREAD_SETNAME)
    int       err;
    pthread_t thread_handle = pthread_self();
    err                     = pthread_setname_np(thread_handle, name);
    if (err != 0) {
        LOG(LEVEL_WARN, "set thread name %" PRIuPTR " %s. Error %d\n",
            thread_handle, name, err);
    }
#else
    (void)name;
#endif
#endif
}

void *pixie_create_barrier(unsigned total_threads) {
#if defined(_WIN32)
    BOOL                      is_succces;
    LPSYNCHRONIZATION_BARRIER p_barrier;
    p_barrier = CALLOC(1, sizeof(SYNCHRONIZATION_BARRIER));
    if (p_barrier == NULL) {
        return NULL;
    }
    is_succces = InitializeSynchronizationBarrier(p_barrier, total_threads, 0);
    if (is_succces == FALSE) {
        FREE(p_barrier);
        return NULL;
    }
    return p_barrier;
#else
    int                res;
    pthread_barrier_t *p_barrier;
    p_barrier = CALLOC(1, sizeof(pthread_barrier_t));
    if (p_barrier == NULL) {
        return NULL;
    }
    res = pthread_barrier_init(p_barrier, NULL, total_threads);
    if (res != 0) {
        FREE(p_barrier);
        return NULL;
    }
    return p_barrier;
#endif
}

void pixie_wait_barrier(void *p_barrier) {
#if defined(_WIN32)
    EnterSynchronizationBarrier(p_barrier,
                                SYNCHRONIZATION_BARRIER_FLAGS_BLOCK_ONLY);
#else
    pthread_barrier_wait(p_barrier);
    return;
#endif
}

bool pixie_delete_barrier(void *p_barrier) {
#if defined(_WIN32)
    BOOL is_succces;
    is_succces = DeleteSynchronizationBarrier(p_barrier);
    free(p_barrier);
    return (bool)is_succces;
#else
    int res;
    res = pthread_barrier_destroy(p_barrier);
    FREE(p_barrier);
    return res == 0;
#endif
}

void *pixie_create_rwlock() {
#if defined(_WIN32)
    PSRWLOCK p_rwlock;
    p_rwlock = CALLOC(1, sizeof(SRWLOCK));
    if (p_rwlock == NULL) {
        return NULL;
    }
    InitializeSRWLock(p_rwlock);
    return p_rwlock;
#else
    int               res;
    pthread_rwlock_t *p_rwlock;
    p_rwlock = CALLOC(1, sizeof(pthread_rwlock_t));
    if (p_rwlock == NULL) {
        return NULL;
    }
    res = pthread_rwlock_init(p_rwlock, NULL);
    if (res != 0) {
        FREE(p_rwlock);
        return NULL;
    }
    return p_rwlock;
#endif
}

void pixie_acquire_rwlock_read(void *p_rwlock) {
#if defined(_WIN32)
    AcquireSRWLockShared(p_rwlock);
#else
    pthread_rwlock_rdlock(p_rwlock);
#endif
}

void pixie_release_rwlock_read(void *p_rwlock) {
#if defined(_WIN32)
    ReleaseSRWLockShared(p_rwlock);
#else
    pthread_rwlock_unlock(p_rwlock);
#endif
}

void pixie_acquire_rwlock_write(void *p_rwlock) {
#if defined(_WIN32)
    AcquireSRWLockExclusive(p_rwlock);
#else
    pthread_rwlock_wrlock(p_rwlock);
#endif
}

void pixie_release_rwlock_write(void *p_rwlock) {
#if defined(_WIN32)
    ReleaseSRWLockExclusive(p_rwlock);
#else
    pthread_rwlock_unlock(p_rwlock);
#endif
}

bool pixie_delete_rwlock(void *p_rwlock) {
#if defined(_WIN32)
    FREE(p_rwlock);
    return true;
#else
    int res;
    res = pthread_rwlock_destroy(p_rwlock);
    FREE(p_rwlock);
    return res == 0;
#endif
}

void *pixie_create_mutex() {
#if defined(_WIN32)
    HANDLE p_mutex;
    p_mutex = CreateMutexW(NULL, FALSE, NULL);
    return (void *)p_mutex;
#else
    int              res;
    pthread_mutex_t *p_mutex;
    p_mutex = CALLOC(1, sizeof(pthread_mutex_t));
    if (p_mutex == NULL) {
        return NULL;
    }
    res = pthread_mutex_init(p_mutex, NULL);
    if (res != 0) {
        FREE(p_mutex);
        return NULL;
    }
    return p_mutex;
#endif
}

void pixie_acquire_mutex(void *p_mutex) {
#if defined(_WIN32)
    WaitForSingleObject((HANDLE)p_mutex, INFINITE);
#else
    pthread_mutex_lock(p_mutex);
#endif
}

void pixie_release_mutex(void *p_mutex) {
#if defined(_WIN32)
    ReleaseMutex((HANDLE)p_mutex);
#else
    pthread_mutex_unlock(p_mutex);
#endif
}

bool pixie_delete_mutex(void *p_mutex) {
#if defined(_WIN32)
    CloseHandle((HANDLE)p_mutex);
    return true;
#else
    int res;
    res = pthread_mutex_destroy(p_mutex);
    FREE(p_mutex);
    return res == 0;
#endif
}