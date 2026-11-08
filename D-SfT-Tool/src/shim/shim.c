/*
 * dsftshim - LD_PRELOAD shim for D-SfT Tool.
 *
 * Loaded into every process of a launched run (env DSFT_SHIM_SOCK is set).
 * Reports over a unix stream socket (newline-terminated lines):
 *   F|pid|ppid|comm       process registered (ctor or fork)
 *   E|pid|argv0|cmdline   exec attempt inside the tree
 *   C|pid|path            file/dir created (open O_CREAT, mkdir)
 *   D|pid|path            file/dir removed (unlink/remove/rmdir)
 *   W|pid|total_bytes     disk-usage progress (~per MB)
 *   I|pid                 process is reading stdin
 *   Q|pid                 DISK QUOTA EXCEEDED
 *
 * Disk accounting lives in POSIX shared memory (per run) so the whole
 * process tree shares one counter; once over quota, writes to regular
 * files fail with ENOSPC (stops the copy), and the GUI then kills the
 * tree and deletes every file the tree created.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/types.h>

#define MAX_FILES  1024
#define PATHBUF    4096
#define FDTAB_SIZE 8192

static void send_ev(const char *fmt, ...);

static __thread int in_init = 0;   /* guard: our own hooks fire during init */

/* debug prints are OFF by default: the shim must stay invisible in the
 * program's real stderr (launch the GUI with DSFT_DEBUG=1 to see them) */
static int shim_dbg(void)
{
    static int v = -1;
    if (v < 0) {
        const char *d = getenv("DSFT_DEBUG");
        v = (d && *d && *d != '0') ? 1 : 0;
    }
    return v;
}

/* real allocator + bootstrap heap (used by the RAM hooks; resolved in
 * shim_init because dlsym itself allocates) */
static void *(*real_malloc_fn)(size_t);
static void *(*real_calloc_fn)(size_t, size_t);
static void *(*real_realloc_fn)(void *, size_t);
static void (*real_free_fn)(void *);
static size_t (*real_usable_fn)(void *);
static char g_boot[1 << 18];
static size_t g_boot_used = 0;
static volatile int g_boot_phase = 1;   /* 1 until real allocator resolved */
static void *boot_alloc(size_t n);

#include "shim_layout.h"

static struct SharedState *S = NULL;
static int cfd = -1;
static char sockpath[PATHBUF];
static volatile int active = 0;
static int fork_reported = 0;   /* set once per image; fork children re-report */
static __thread int ev_busy = 0;/* no recursive event sends */

struct FdTrack { off_t base; uint64_t counted; uint32_t idx; char track; char pseudo; };
static struct FdTrack fdtab[FDTAB_SIZE];

/* ---------------- init ---------------- */

static void get_comm(char *out, size_t n)
{
    int fd = open("/proc/self/comm", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, out, n - 1);
        close(fd);
        if (r > 0) { out[r] = 0;
            while (r > 0 && (out[r-1] == '\n' || out[r-1] == '\r')) out[--r] = 0;
            return; }
    }
    snprintf(out, n, "?");
}

static void report_self(void)
{
    char comm[64];
    get_comm(comm, sizeof comm);
    send_ev("F|%d|%d|%s", (int)getpid(), (int)getppid(), comm);
}

static void shim_init(void)
{
    in_init = 1;
    /* resolve the real allocator FIRST — dlsym itself allocates, those
     * allocations are served by the boot heap (see boot_alloc) */
    real_malloc_fn  = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    real_calloc_fn  = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
    real_realloc_fn = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
    real_free_fn    = (void (*)(void *))dlsym(RTLD_NEXT, "free");
    real_usable_fn  = (size_t (*)(void *))dlsym(RTLD_NEXT, "malloc_usable_size");
    g_boot_phase = 0;
    if (shim_dbg()) fprintf(stderr, "[shim] dlsym resolved\n");

    const char *sp = getenv("DSFT_SHIM_SOCK");
    if (!sp || !*sp) { in_init = 0; return; }
    snprintf(sockpath, sizeof sockpath, "%s", sp);

    const char *shname = getenv("DSFT_SHM_NAME");
    if (!shname || !*shname) return;

    int created = 0;
    int fd = shm_open(shname, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd >= 0) created = 1;
    else fd = shm_open(shname, O_RDWR, 0600);
    if (fd < 0) { in_init = 0; return; }

    /* heal stale/undersized segments instead of SIGBUSing on mmap */
    struct stat st;
    int heal = 0;
    if (!created && fstat(fd, &st) == 0 && st.st_size < (off_t)sizeof(struct SharedState))
        heal = 1;
    if ((created || heal) && ftruncate(fd, (off_t)sizeof(struct SharedState)) != 0) {
        close(fd); in_init = 0; return;
    }
    S = (struct SharedState *)mmap(NULL, sizeof(struct SharedState),
                                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (S == MAP_FAILED) { S = NULL; in_init = 0; return; }

    if (created || heal) {
        pthread_mutexattr_t ma;
        pthread_mutexattr_init(&ma);
        pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(&S->lock, &ma);
        const char *q = getenv("DSFT_QUOTA_MB");
        S->limit_mb = q ? (uint32_t)strtoul(q, NULL, 10) : 0;
        const char *rb = getenv("DSFT_RAM_MB");
        S->ram_limit_mb = rb ? (uint32_t)strtoul(rb, NULL, 10) : 0;
        const char *rm = getenv("DSFT_RAM_MODE");
        S->ram_mode = rm ? (uint8_t)atoi(rm) : 0;
        const char *db = getenv("DSFT_DISK_BLOCK");
        S->disk_block = db ? (uint8_t)atoi(db) : 1;
        S->written = 0; S->gross = 0; S->ram = 0; S->ram_peak = 0;
        S->over = 0; S->nfiles = 0;
        memset(S->files, 0, sizeof S->files);
        memset(S->filepid, 0, sizeof S->filepid);
        memset(S->filecontrib, 0, sizeof S->filecontrib);
    } else {
        /* recover a mutex left locked by a killed process */
        int rc = pthread_mutex_lock(&S->lock);
        if (rc == EOWNERDEAD) pthread_mutex_consistent(&S->lock);
        if (rc == 0 || rc == EOWNERDEAD) pthread_mutex_unlock(&S->lock);
    }

    if (shim_dbg()) fprintf(stderr, "[shim] shm mapped (created=%d)\n", created);
    int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s >= 0) {
        struct sockaddr_un a;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        strncpy(a.sun_path, sockpath, sizeof(a.sun_path) - 1);
        if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) cfd = s;
        else close(s);
    }

    { if (shim_dbg()) { const char m[] = "[shim] init done\n"; write(2, m, sizeof m - 1); } }
    active = 1;
    fork_reported = 1;
    /* NOTE: in_init intentionally STAYS 1 — clearing this TLS guard from
     * inside the constructor deadlocks later hooked calls (futex hang).
     * "init finished" is signalled by active=1 instead. */
    report_self();
}

static pthread_once_t once = PTHREAD_ONCE_INIT;
static void shim_boot(void) { if (in_init) return; pthread_once(&once, shim_init); }

/* ---------------- events ---------------- */

void send_ev(const char *fmt, ...)
{
    if (!active || cfd < 0 || ev_busy) return;
    ev_busy = 1;
    char buf[PATHBUF + 256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n > (int)(sizeof buf - 2)) n = (int)(sizeof buf - 2);
        buf[n] = '\n'; buf[n + 1] = 0;
        send(cfd, buf, (size_t)n + 1, MSG_NOSIGNAL);
    }
    ev_busy = 0;
}

/* ---------------- accounting ---------------- */

static int fd_isreg(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
}

static int fd_pseudo(int fd)
{
    return fd >= 0 && fd < FDTAB_SIZE && fdtab[fd].pseudo;
}

/* real stdin feeding (the GUI's pipe) vs a terminal's pty: only announce
 * "waiting for input" for pipes, so interactive shells don't spam */
static int stdin_is_pipe(void)
{
    struct stat st;
    return fstat(0, &st) == 0 && S_ISFIFO(st.st_mode);
}

/* kernel/pseudo filesystems: not real disk — no events, no accounting */
static int is_pseudo(const char *p)
{
    return p && (strncmp(p, "/proc/", 6) == 0 || strncmp(p, "/sys/", 5) == 0 ||
                 strncmp(p, "/dev/", 5) == 0 || strncmp(p, "/run/", 5) == 0);
}

static void bind_fd(int fd, int write_flags, int idx, int pseudo)
{
    if (fd < 0 || fd >= FDTAB_SIZE) return;
    fdtab[fd].idx = (uint32_t)(idx >= 0 ? idx : 0xFFFFFFFFu);
    fdtab[fd].pseudo = (char)pseudo;
    if (!write_flags || pseudo) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return;
    fdtab[fd].base = st.st_size;
    fdtab[fd].counted = 0;
    fdtab[fd].track = 1;
}

/* returns 1 if now over quota. Emits W meter events itself so EVERY
 * accounting path (write/fwrite/pwrite/close/mkdir) updates the GUI live. */
static int account(ssize_t bytes, uint64_t *total_out)
{
    if (!S || bytes <= 0) { if (total_out) *total_out = S ? S->written : 0; return 0; }
    int rc = pthread_mutex_lock(&S->lock);
    if (rc == EOWNERDEAD) { pthread_mutex_consistent(&S->lock); rc = 0; }
    if (rc != 0) { if (total_out) *total_out = 0; return 0; }
    S->written += (uint64_t)bytes;
    S->gross += (uint64_t)bytes;
    /* reaching the limit counts (usage 90/90 stops) — not strictly beyond */
    if (S->limit_mb > 0 && S->written >= (uint64_t)S->limit_mb * 1024ULL * 1024ULL)
        S->over = 1;
    uint64_t w = S->written;
    int over = (int)S->over;
    uint32_t lim = S->limit_mb;
    pthread_mutex_unlock(&S->lock);
    if (total_out) *total_out = w;
    static __thread uint64_t last_mb = (uint64_t)-1;
    uint64_t mb = w / (1024ULL * 1024ULL);
    if (mb != last_mb) { last_mb = mb; send_ev("W|%d|%llu", (int)getpid(), (unsigned long long)w); }
    if (over && lim > 0) {
        static __thread int q_sent = 0;
        if (!q_sent) { q_sent = 1; send_ev("Q|%d", (int)getpid()); }
    }
    return over;
}

/* attribute bytes to a table entry (dir creation, close flushes, ...) */
static void add_contrib(int idx, uint64_t bytes)
{
    if (!S || idx < 0 || idx >= MAX_FILES || bytes == 0) return;
    int rc = pthread_mutex_lock(&S->lock);
    if (rc == EOWNERDEAD) { pthread_mutex_consistent(&S->lock); rc = 0; }
    if (rc != 0) return;
    S->filecontrib[idx] += bytes;
    pthread_mutex_unlock(&S->lock);
}

/* ---------------- heap (RAM) accounting + own-ram jail ---------------- */

#include <malloc.h>

static uint64_t ram_usable(void *p)
{
    return p ? (uint64_t)malloc_usable_size(p) : 0;
}

/* heap accounting: delta in bytes; emits R meter events (per MB) and the
 * RQ terminate trigger when the RAM limit is reached */
static void ram_account(int64_t delta)
{
    if (!S || delta == 0 || !active) return;
    int rc = pthread_mutex_lock(&S->lock);
    if (rc == EOWNERDEAD) { pthread_mutex_consistent(&S->lock); rc = 0; }
    if (rc != 0) return;
    if (delta < 0 && (uint64_t)(-delta) > S->ram) S->ram = 0;
    else S->ram = (uint64_t)((int64_t)S->ram + delta);
    if (S->ram > S->ram_peak) S->ram_peak = S->ram;
    const int over = (S->ram_mode == 1 && S->ram_limit_mb > 0 &&
                      S->ram >= (uint64_t)S->ram_limit_mb * 1024ULL * 1024ULL);
    const uint64_t r = S->ram;
    pthread_mutex_unlock(&S->lock);

    static __thread uint64_t last_mb = (uint64_t)-1;
    const uint64_t mb = r / (1024ULL * 1024ULL);
    if (mb != last_mb) { last_mb = mb; send_ev("R|%d|%llu", (int)getpid(), (unsigned long long)r); }
    static __thread int rq_sent = 0;
    if (over) {
        if (!rq_sent) { rq_sent = 1; send_ev("RQ|%d", (int)getpid()); }
    } else {
        rq_sent = 0;      /* re-arm: usage dropped back under the limit */
    }
}

/* own-ram jail: does this allocation exceed the jail? */
static int ram_jail_blocks(size_t size)
{
    if (!S || !active || S->ram_mode != 2 || S->ram_limit_mb == 0) return 0;
    if (S->ram + (uint64_t)size <= (uint64_t)S->ram_limit_mb * 1024ULL * 1024ULL) return 0;
    static __thread time_t last = 0;
    time_t now = time(NULL);
    if (now - last >= 1) {
        last = now;
        send_ev("RM|%d|%llu", (int)getpid(), (unsigned long long)S->ram);
    }
    return 1;
}

/* ---- bootstrap allocator: serves mallocs that happen while we are still
 * resolving the real allocator (dlsym itself allocates) ---- */
static int in_boot_range(const void *p)
{
    return (const char *)p >= g_boot && (const char *)p < g_boot + sizeof g_boot;
}

static void *boot_alloc(size_t n)
{
    n = (n + 31) & ~(size_t)31;
    if (g_boot_used + n + 32 > sizeof g_boot) return NULL;
    char *p = g_boot + g_boot_used;
    g_boot_used += n + 32;
    ((size_t *)p)[0] = n;                 /* size header for realloc */
    return p + 32;
}

static size_t boot_size(const void *p)
{
    return p ? ((const size_t *)p)[-1] : 0;
}

static int m1 = 0;
void *malloc(size_t size)
{
    shim_boot();
    if (g_boot_phase || !real_malloc_fn) return boot_alloc(size);
    if (ram_jail_blocks(size)) return NULL;
    void *p = real_malloc_fn(size);
    if (p) ram_account((int64_t)ram_usable(p));
    return p;
}

void *calloc(size_t nmemb, size_t size)
{
    shim_boot();
    size_t total = nmemb * size;
    if (nmemb && size && total / nmemb != size) return NULL;
    if (g_boot_phase || !real_calloc_fn) {
        void *p = boot_alloc(total);
        if (p) memset(p, 0, total);
        return p;
    }
    if (ram_jail_blocks(total)) return NULL;
    void *p = real_calloc_fn(nmemb, size);
    if (p) ram_account((int64_t)ram_usable(p));
    return p;
}

void *realloc(void *ptr, size_t size)
{
    shim_boot();
    if (ptr && in_boot_range(ptr)) {
        const size_t old = boot_size(ptr);
        void *np = malloc(size);
        if (np) memcpy(np, ptr, old < size ? old : size);
        return np;
    }
    if (g_boot_phase || !real_realloc_fn) return NULL;
    const uint64_t oldu = ptr ? ram_usable(ptr) : 0;
    if (ram_jail_blocks(size) && size > oldu) { return NULL; }
    void *p = real_realloc_fn(ptr, size);
    if (p) ram_account((int64_t)ram_usable(p) - (int64_t)oldu);
    return p;
}

void free(void *ptr)
{
    shim_boot();
    if (!ptr) return;
    if (in_boot_range(ptr)) return;       /* boot heap is never released */
    if (g_boot_phase || !real_free_fn) return;
    const uint64_t u = ram_usable(ptr);
    real_free_fn(ptr);
    if (u) ram_account(-(int64_t)u);
}

/* NOTE: posix_memalign / aligned_alloc are deliberately NOT hooked. An
 * aligned allocator must return a pointer that the REAL free() accepts;
 * returning an interior pointer of a bigger malloc block crashes the app
 * the first time it frees (reproduced: konsole SIGSEGV'd instantly).
 * Aligned allocations therefore bypass RAM accounting — documented. */

/* find-or-add a table entry; sends the C event. returns table idx or -1 */
static int add_created(const char *path)
{
    if (!S || !path || !*path || is_pseudo(path)) return -1;
    int idx = -1;
    int rc = pthread_mutex_lock(&S->lock);
    if (rc == EOWNERDEAD) { pthread_mutex_consistent(&S->lock); rc = 0; }
    if (rc != 0) return -1;
    for (uint32_t i = 0; i < S->nfiles; ++i)
        if (strncmp(S->files[i], path, PATHBUF) == 0) { idx = (int)i; break; }
    if (idx < 0 && S->nfiles < MAX_FILES) {
        idx = (int)S->nfiles++;
        snprintf(S->files[idx], PATHBUF, "%s", path);
        S->filepid[idx] = (uint32_t)getpid();
        S->filecontrib[idx] = 0;
    }
    pthread_mutex_unlock(&S->lock);
    if (idx >= 0) send_ev("C|%d|%s", (int)getpid(), path);
    return idx;
}

/* tree-created file removed: subtract its counted bytes from the net usage */
static void remove_created(const char *path)
{
    if (!S || !path || !*path || is_pseudo(path)) return;
    uint64_t freed = 0;
    uint64_t remaining = 0;
    int rc = pthread_mutex_lock(&S->lock);
    if (rc == EOWNERDEAD) { pthread_mutex_consistent(&S->lock); rc = 0; }
    if (rc != 0) return;
    for (uint32_t i = 0; i < S->nfiles; ++i) {
        if (strncmp(S->files[i], path, PATHBUF) == 0) {
            if (S->filecontrib[i] <= S->written) S->written -= S->filecontrib[i];
            else S->written = 0;
            freed = S->filecontrib[i];
            uint32_t last = S->nfiles - 1;
            if (i != last) {
                memcpy(S->files[i], S->files[last], PATHBUF);
                S->filepid[i] = S->filepid[last];
                S->filecontrib[i] = S->filecontrib[last];
            }
            S->files[last][0] = 0;
            S->filepid[last] = 0;
            S->filecontrib[last] = 0;
            S->nfiles--;
            break;
        }
    }
    remaining = S->written;
    /* delete-mode: the GUI frees files and resets `over` so the program can
     * continue (limited but alive) — re-arm the Q event per process too */
    if (S->limit_mb > 0 && S->written < (uint64_t)S->limit_mb * 1024ULL * 1024ULL)
        S->over = 0;
    pthread_mutex_unlock(&S->lock);
    if (freed > 0)   /* meter drops live when the app frees space */
        send_ev("W|%d|%llu", (int)getpid(), (unsigned long long)remaining);
}

/* rename of a tree-created file: keep contrib, update the path */
static void rename_created(const char *oldp, const char *newp)
{
    if (!S || !oldp || !newp || is_pseudo(oldp) || is_pseudo(newp)) return;
    int rc = pthread_mutex_lock(&S->lock);
    if (rc == EOWNERDEAD) { pthread_mutex_consistent(&S->lock); rc = 0; }
    if (rc != 0) return;
    for (uint32_t i = 0; i < S->nfiles; ++i)
        if (strncmp(S->files[i], oldp, PATHBUF) == 0) {
            snprintf(S->files[i], PATHBUF, "%s", newp);
            break;
        }
    pthread_mutex_unlock(&S->lock);
}

/* ---------------- path helpers ---------------- */

static void resolve_path(int dirfd, const char *path, char *out, size_t outn)
{
    out[0] = 0;
    if (!path || !*path) return;
    if (path[0] == '/') { snprintf(out, outn, "%s", path); return; }
    char cwd[PATHBUF];
    if (dirfd == AT_FDCWD || dirfd < 0) {
        if (getcwd(cwd, sizeof cwd))
            snprintf(out, outn, "%s/%s", cwd, path);
        else
            snprintf(out, outn, "%s", path);
        return;
    }
    char link[PATHBUF];
    char p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", dirfd);
    ssize_t r = readlink(p, link, sizeof link - 1);
    if (r > 0) { link[r] = 0; snprintf(out, outn, "%s/%s", link, path); }
    else snprintf(out, outn, "%s", path);
}

/* ---------------- syscall hook implementations ---------------- */

#define NEXT(sym) ({ \
    static __typeof__(&sym) p = NULL; \
    if (!p) p = (__typeof__(&sym))dlsym(RTLD_NEXT, #sym); \
    p; })

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    shim_boot();
    int fd = NEXT(open)(path, flags, mode);
    if (fd >= 0 && (flags & O_CREAT)) {
        char full[PATHBUF]; resolve_path(AT_FDCWD, path, full, sizeof full);
        int idx = add_created(full);
        bind_fd(fd, flags & (O_WRONLY | O_RDWR), idx, is_pseudo(full));
    }
    return fd;
}

int open64(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    shim_boot();
    int fd = NEXT(open64)(path, flags, mode);
    if (fd >= 0 && (flags & O_CREAT)) {
        char full[PATHBUF]; resolve_path(AT_FDCWD, path, full, sizeof full);
        int idx = add_created(full);
        bind_fd(fd, flags & (O_WRONLY | O_RDWR), idx, is_pseudo(full));
    }
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    shim_boot();
    int fd = NEXT(openat)(dirfd, path, flags, mode);
    if (fd >= 0 && (flags & O_CREAT)) {
        char full[PATHBUF]; resolve_path(dirfd, path, full, sizeof full);
        int idx = add_created(full);
        bind_fd(fd, flags & (O_WRONLY | O_RDWR), idx, is_pseudo(full));
    }
    return fd;
}

int creat(const char *path, mode_t mode)
{
    shim_boot();
    int fd = NEXT(creat)(path, mode);
    if (fd >= 0) {
        char full[PATHBUF]; resolve_path(AT_FDCWD, path, full, sizeof full);
        int idx = add_created(full);
        bind_fd(fd, 1, idx, is_pseudo(full));
    }
    return fd;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    shim_boot();
    if (S && S->over && S->limit_mb > 0 && S->disk_block && fd_isreg(fd) && !fd_pseudo(fd)) { errno = ENOSPC; return -1; }
    ssize_t r = NEXT(write)(fd, buf, count);
    if (r > 0 && S && fd_isreg(fd) && !fd_pseudo(fd)) {
        account(r, NULL);
        if (fd < FDTAB_SIZE && fdtab[fd].track) fdtab[fd].counted += (uint64_t)r;
    }
    return r;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t off)
{
    shim_boot();
    if (S && S->over && S->limit_mb > 0 && S->disk_block && fd_isreg(fd) && !fd_pseudo(fd)) { errno = ENOSPC; return -1; }
    ssize_t r = NEXT(pwrite)(fd, buf, count, off);
    if (r > 0 && S && fd_isreg(fd)) account(r, NULL);
    return r;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    shim_boot();
    if (S && S->over && S->limit_mb > 0 && S->disk_block && fd_isreg(fd) && !fd_pseudo(fd)) { errno = ENOSPC; return -1; }
    ssize_t r = NEXT(writev)(fd, iov, iovcnt);
    if (r > 0 && S && fd_isreg(fd)) account(r, NULL);
    return r;
}

int close(int fd)
{
    shim_boot();
    /* flush size-based accounting for fds opened through us (stdio path) and
     * attribute the file's total counted bytes to its table entry */
    if (fd >= 0 && fd < FDTAB_SIZE && fdtab[fd].track && S) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
            off_t sz = st.st_size > fdtab[fd].base ? st.st_size - fdtab[fd].base : 0;
            if ((uint64_t)sz > fdtab[fd].counted) account((ssize_t)(sz - fdtab[fd].counted), NULL);
            const uint64_t fdTotal = fdtab[fd].counted > (uint64_t)sz
                                         ? fdtab[fd].counted : (uint64_t)sz;
            if (fdtab[fd].idx != 0xFFFFFFFFu) {
                int rc = pthread_mutex_lock(&S->lock);
                if (rc == EOWNERDEAD) { pthread_mutex_consistent(&S->lock); rc = 0; }
                if (rc == 0) {
                    if (fdtab[fd].idx < MAX_FILES)
                        S->filecontrib[fdtab[fd].idx] += fdTotal;
                    pthread_mutex_unlock(&S->lock);
                }
            }
        }
        fdtab[fd].track = 0; fdtab[fd].counted = 0; fdtab[fd].base = 0;
        fdtab[fd].idx = 0xFFFFFFFFu;
    }
    return NEXT(close)(fd);
}

int unlink(const char *path)
{
    shim_boot();
    char full[PATHBUF]; resolve_path(AT_FDCWD, path, full, sizeof full);
    int r = NEXT(unlink)(path);
    if (r == 0 && !is_pseudo(full)) { remove_created(full);
                  send_ev("D|%d|%s", (int)getpid(), full); }
    return r;
}

int unlinkat(int dirfd, const char *path, int flags)
{
    shim_boot();
    char full[PATHBUF]; resolve_path(dirfd, path, full, sizeof full);
    int r = NEXT(unlinkat)(dirfd, path, flags);
    if (r == 0 && !is_pseudo(full)) { remove_created(full);
                  send_ev("D|%d|%s", (int)getpid(), full); }
    return r;
}

int remove(const char *path)
{
    shim_boot();
    char full[PATHBUF]; resolve_path(AT_FDCWD, path, full, sizeof full);
    int r = NEXT(remove)(path);
    if (r == 0 && !is_pseudo(full)) { remove_created(full);
                  send_ev("D|%d|%s", (int)getpid(), full); }
    return r;
}

int rmdir(const char *path)
{
    shim_boot();
    char full[PATHBUF]; resolve_path(AT_FDCWD, path, full, sizeof full);
    int r = NEXT(rmdir)(path);
    if (r == 0 && !is_pseudo(full)) { remove_created(full);
                  send_ev("D|%d|%s", (int)getpid(), full); }
    return r;
}

int rename(const char *oldp, const char *newp)
{
    shim_boot();
    int r = NEXT(rename)(oldp, newp);
    if (r == 0) {
        char fo[PATHBUF], fn[PATHBUF];
        resolve_path(AT_FDCWD, oldp, fo, sizeof fo);
        resolve_path(AT_FDCWD, newp, fn, sizeof fn);
        rename_created(fo, fn);
        if (!is_pseudo(fo)) send_ev("D|%d|%s", (int)getpid(), fo);
        if (!is_pseudo(fn)) send_ev("C|%d|%s", (int)getpid(), fn);
    }
    return r;
}

int mkdir(const char *path, mode_t mode)
{
    shim_boot();
    int r = NEXT(mkdir)(path, mode);
    if (r == 0) {
        char full[PATHBUF]; resolve_path(AT_FDCWD, path, full, sizeof full);
        int idx = add_created(full);
        /* a new directory costs a disk block (~4 KB) — count it even when the
         * tracking table is full, so mass-creators still hit the quota */
        account(4096, NULL);
        add_contrib(idx, 4096);
    }
    return r;
}

int truncate(const char *path, off_t len)
{
    shim_boot();
    int r = NEXT(truncate)(path, len);
    if (r == 0 && S) account(len, NULL);
    return r;
}

int ftruncate(int fd, off_t len)
{
    shim_boot();
    int r = NEXT(ftruncate)(fd, len);
    if (r == 0 && S && fd_isreg(fd)) account(len, NULL);
    return r;
}

/* stdio fopen goes through glibc-internal open64 which bypasses our open
 * hook — hook fopen so stdio-created files are detected + tracked. */
static FILE *fopen_common(FILE *s, const char *path, const char *mode)
{
    if (s && path) {
        const int wr = mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+'));
        int idx = -1;
        char full[PATHBUF];
        int pseudo = 0;
        if (wr) {
            resolve_path(AT_FDCWD, path, full, sizeof full);
            pseudo = is_pseudo(full);
            idx = add_created(full);   /* sends the C event */
        }
        const int fd = fileno(s);
        bind_fd(fd, wr, idx, pseudo);
    }
    return s;
}

FILE *fopen(const char *path, const char *mode)
{
    shim_boot();
    return fopen_common(NEXT(fopen)(path, mode), path, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    shim_boot();
    return fopen_common(NEXT(fopen64)(path, mode), path, mode);
}

/* stdio fwrite goes through glibc-internal write() which bypasses our write
 * hook — hook fwrite itself so buffered writes are accounted immediately.
 * (fwrite_unlocked is an inline in glibc's headers and can't be redefined.) */
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *s)
{
    shim_boot();
    if (S && S->over && S->limit_mb > 0 && S->disk_block) {
        int fd = s ? fileno(s) : -1;
        if (fd >= 0 && fd_isreg(fd) && !fd_pseudo(fd)) { errno = ENOSPC; return 0; }
    }
    size_t r = NEXT(fwrite)(ptr, size, nmemb, s);
    if (r > 0 && S && s) {
        int fd = fileno(s);
        if (fd >= 0 && fd_isreg(fd)) account((ssize_t)(size * r), NULL);
    }
    return r;
}

char *fgets(char *s, int size, FILE *stream)
{
    shim_boot();
    if (stream && fileno(stream) == 0 && stdin_is_pipe()) {
        static __thread time_t last_i = 0;
        time_t now = time(NULL);
        if (now - last_i >= 1) { last_i = now; send_ev("I|%d", (int)getpid()); }
    }
    return NEXT(fgets)(s, size, stream);
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    shim_boot();
    if (stream && fileno(stream) == 0 && stdin_is_pipe()) {
        static __thread time_t last_g = 0;
        time_t now = time(NULL);
        if (now - last_g >= 1) { last_g = now; send_ev("I|%d", (int)getpid()); }
    }
    return NEXT(getline)(lineptr, n, stream);
}

ssize_t read(int fd, void *buf, size_t count)
{
    shim_boot();
    if (fd == 0 && stdin_is_pipe()) {
        static __thread time_t last_i = 0;
        time_t now = time(NULL);
        if (now - last_i >= 1) { last_i = now; send_ev("I|%d", (int)getpid()); }
    }
    ssize_t r = NEXT(read)(fd, buf, count);
    return r;
}

static void log_exec(const char *argv0, char *const argv[])
{
    if (!active) return;
    char cmd[1024];
    size_t pos = 0;
    if (argv) {
        for (int i = 0; argv[i]; ++i) {
            int w = snprintf(cmd + pos, sizeof cmd - pos, "%s%s", i ? " " : "", argv[i]);
            if (w < 0 || (size_t)w >= sizeof cmd - pos) break;
            pos += (size_t)w;
        }
    } else {
        snprintf(cmd, sizeof cmd, "%s", argv0 ? argv0 : "?");
    }
    char a0[256];
    snprintf(a0, sizeof a0, "%s", argv0 ? argv0 : "?");
    char *slash = strrchr(a0, '/');
    if (slash) memmove(a0, slash + 1, strlen(slash + 1) + 1);
    send_ev("E|%d|%s|%s", (int)getpid(), a0, cmd);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    shim_boot();
    log_exec(path, argv);
    return NEXT(execve)(path, argv, envp);
}

int execvp(const char *file, char *const argv[])
{
    shim_boot();
    log_exec(file, argv);
    return NEXT(execvp)(file, argv);
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    shim_boot();
    log_exec(file, argv);
    return NEXT(execvpe)(file, argv, envp);
}

pid_t fork(void)
{
    shim_boot();
    pid_t pid = NEXT(fork)();
    if (pid == 0 && !fork_reported) { fork_reported = 1; report_self(); }
    return pid;
}

__attribute__((constructor(101)))
static void shim_ctor(void)
{
    shim_boot();
    if (shim_dbg()) { const char m[] = "[shim] ctor done\n"; write(2, m, sizeof m - 1); }
}
