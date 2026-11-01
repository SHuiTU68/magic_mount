/*
 * magic_mount.c -- tmpfs-backed, zero-copy mount core (C implementation)
 *
 * Design goals
 * ------------
 *  1. Every runtime write and every mount object lives in one private,
 *     randomly named tmpfs.  Physical disk I/O is never performed: the
 *     workspace only contains empty placeholder files, directories and
 *     symlinks, all of which are tmpfs inodes.
 *
 *  2. Path lookup depth is kept minimal:
 *       - plain file replacement  -> 1 extra vfsmount (direct bind on the
 *         final path, no skeleton around it);
 *       - directory that must become a skeleton (opaque/dir replacement,
 *         new entry, symlink, whiteout) -> 1 extra mount for the directory
 *         itself, +1 for the files that have to be bound inside it.
 *     Nothing is ever bound onto an already bound target, so the vfsmount
 *     chain never grows beyond "native mount + 1 (or 2 inside a skeleton)".
 *
 *  3. Stealth: the workspace mount point has a random name, is made
 *     private, never appears on a stable path, and is detached + removed
 *     before returning.  Each created mount mirrors the mount flags of the
 *     native mount it covers (ro/nosuid/nodev/noexec/atime), so `mount`,
 *     `findmnt`, `statfs`-flag checks see the same attributes as the stock
 *     mount.  Skeleton mounts are assembled on the workspace and attached
 *     with one move_mount, so a partially populated directory is never
 *     visible.
 *
 *  4. The work inside one directory (file binds and mirrored entries) is
 *     independent, so it runs on a small bounded thread pool.  The tree walk
 *     itself stays ordered: a skeleton is rooted before its children are
 *     mounted and attached only once it is complete.  The thread budget is
 *     process-global, so nested directories fall back to inline work instead
 *     of multiplying threads.
 *
 * Build (Android):
 *     aarch64-linux-android-clang -O2 -Wall -Wextra -c magic_mount.c
 * Build (host test):
 *     gcc -O2 -Wall -Wextra -DMM_MODULE_DIR='"/tmp/x/modules"' \
 *         -DMM_ROOT_PREFIX='"/tmp/x/root"' magic_mount.c -o magic_mount
 * Run:  magic_mount [-v] [-s <tmpfs-source-name>]
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "kernel/magic_hide/magic_hide_uapi.h"

/* ------------------------------------------------------------------ */
/* compile-time knobs                                                  */
/* ------------------------------------------------------------------ */

#ifndef MM_MODULE_DIR
#define MM_MODULE_DIR "/data/adb/modules"
#endif

/* Prefix prepended to every target path ("/system" -> MM_ROOT_PREFIX
 * "/system").  Empty on a device; a test root when building host tests. */
#ifndef MM_ROOT_PREFIX
#define MM_ROOT_PREFIX ""
#endif

#define MM_WS_SIZE "size=64m,mode=0700"
#define MM_OPAQUE_XATTR "trusted.overlay.opaque"
#define MM_SELINUX_XATTR "security.selinux"
#define MM_DEFAULT_SOURCE "tmpfs"

/* ------------------------------------------------------------------ */
/* logging                                                             */
/* ------------------------------------------------------------------ */

static bool g_verbose;

/* Worker threads log concurrently; keep one line per lock so the output of
 * parallel mounts stays readable. */
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

static void mm_info(const char *fmt, ...) {
    va_list ap;
    pthread_mutex_lock(&g_log_mu);
    fputs("[magic_mount] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    pthread_mutex_unlock(&g_log_mu);
}

static void mm_dbg(const char *fmt, ...) {
    va_list ap;
    if (!g_verbose)
        return;
    pthread_mutex_lock(&g_log_mu);
    fputs("[magic_mount] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    pthread_mutex_unlock(&g_log_mu);
}

static void mm_err(const char *fmt, ...) {
    va_list ap;
    pthread_mutex_lock(&g_log_mu);
    fputs("[magic_mount] ERROR: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    pthread_mutex_unlock(&g_log_mu);
}

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static char *mm_join(const char *base, const char *name) {
    size_t bl, nl;
    bool slash;
    char *r;

    if (!base || !*base) {
        if (!name || !*name)
            return strdup("");
        if (name[0] == '/')
            return strdup(name);
        nl = strlen(name);
        r = malloc(nl + 2);
        if (!r)
            return NULL;
        r[0] = '/';
        memcpy(r + 1, name, nl + 1);
        return r;
    }

    bl = strlen(base);
    nl = name ? strlen(name) : 0;
    slash = bl > 0 && base[bl - 1] != '/';
    while (nl && name[0] == '/') { /* strip leading slashes of name */
        name++;
        nl--;
    }
    r = malloc(bl + (slash ? 1 : 0) + nl + 1);
    if (!r)
        return NULL;
    memcpy(r, base, bl);
    if (slash)
        r[bl++] = '/';
    if (nl)
        memcpy(r + bl, name, nl);
    r[bl + nl] = '\0';
    return r;
}

static bool mm_exists(const char *path) {
    struct stat st;
    return path && *path && lstat(path, &st) == 0;
}

static bool mm_dir_exists(const char *path) {
    struct stat st;
    return path && *path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int mm_copy_label(const char *src, const char *dst) {
    char buf[256];
    ssize_t n = lgetxattr(src, MM_SELINUX_XATTR, buf, sizeof(buf));
    if (n <= 0)
        return -1;
    if (lsetxattr(dst, MM_SELINUX_XATTR, buf, (size_t)n, 0) < 0)
        return -1;
    return 0;
}

static bool mm_is_opaque(const char *dir) {
    char buf[8];
    ssize_t n = lgetxattr(dir, MM_OPAQUE_XATTR, buf, sizeof(buf) - 1);
    if (n <= 0)
        return false;
    buf[n] = '\0';
    return strcmp(buf, "y") == 0;
}

/* Apply mode/owner/SELinux label of src (native or module path) to dst. */
static void mm_copy_dir_meta(const char *src, const char *dst) {
    struct stat st;
    if (src && lstat(src, &st) == 0) {
        chmod(dst, st.st_mode & 07777);
        if (lchown(dst, st.st_uid, st.st_gid) < 0)
            mm_dbg("chown %s: %s", dst, strerror(errno));
    }
    if (src)
        mm_copy_label(src, dst);
}

/* Create an empty placeholder (tmpfs inode, zero bytes written). */
static int mm_touch(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return errno == EEXIST ? 0 : -1;
    close(fd);
    return 0;
}

/* mkdir -p, but only ever used on paths inside the tmpfs workspace. */
static int mm_mkdirs(const char *path) {
    char *tmp = strdup(path);
    char *p;
    int rc = 0;

    if (!tmp)
        return -1;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
                rc = -1;
                break;
            }
            *p = '/';
        }
    }
    if (rc == 0 && mkdir(tmp, 0755) < 0 && errno != EEXIST)
        rc = -1;
    free(tmp);
    return rc;
}

/* ------------------------------------------------------------------ */
/* mountinfo snapshot: used for flag mirroring and for the depth audit  */
/* ------------------------------------------------------------------ */

struct mnt {
    int id;
    int parent;
    char *point;
    char *opts;
    struct mnt *next;
};

static struct mnt *g_mnt;

static char *mm_unescape(const char *s) {
    char *r = strdup(s);
    char *p;
    if (!r)
        return NULL;
    for (p = r; *p; p++) {
        if (p[0] == '\\' && p[1] >= '0' && p[1] <= '7' &&
            p[2] >= '0' && p[2] <= '7' && p[3] >= '0' && p[3] <= '7') {
            char oct[4] = { p[1], p[2], p[3], 0 };
            *p = (char)((oct[0] - '0') * 64 + (oct[1] - '0') * 8 + (oct[2] - '0'));
            memmove(p + 1, p + 4, strlen(p + 4) + 1);
        }
    }
    return r;
}

static void mm_mi_free(void) {
    while (g_mnt) {
        struct mnt *n = g_mnt->next;
        free(g_mnt->point);
        free(g_mnt->opts);
        free(g_mnt);
        g_mnt = n;
    }
}

static int mm_mi_load(void) {
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    struct mnt *tail = NULL;

    mm_mi_free();
    f = fopen("/proc/self/mountinfo", "r");
    if (!f)
        return -1;
    while (getline(&line, &cap, f) > 0) {
        char *sep, *save = NULL, *id_s, *par_s, *pt_s, *opt_s;
        struct mnt *m;

        sep = strstr(line, " - ");
        if (!sep)
            continue;
        id_s = strtok_r(line, " ", &save);
        par_s = strtok_r(NULL, " ", &save);
        (void)strtok_r(NULL, " ", &save);  /* major:minor */
        (void)strtok_r(NULL, " ", &save);  /* root           */
        pt_s = strtok_r(NULL, " ", &save);
        opt_s = strtok_r(NULL, " ", &save);
        if (!id_s || !par_s || !pt_s || !opt_s)
            continue;

        m = calloc(1, sizeof(*m));
        if (!m)
            break;
        m->id = atoi(id_s);
        m->parent = atoi(par_s);
        m->point = mm_unescape(pt_s);
        m->opts = strdup(opt_s);
        if (tail)
            tail->next = m;
        else
            g_mnt = m;
        tail = m;
    }
    free(line);
    fclose(f);
    return 0;
}

static struct mnt *mm_mi_by_id(int id) {
    struct mnt *m;
    for (m = g_mnt; m; m = m->next)
        if (m->id == id)
            return m;
    return NULL;
}

/* Is "mountpoint" a prefix of "path" in path-resolution terms? */
static bool mm_under(const char *mnt_pt, const char *path) {
    size_t n;
    if (!mnt_pt || !path)
        return false;
    if (strcmp(mnt_pt, "/") == 0)
        return true;
    n = strlen(mnt_pt);
    if (strncmp(path, mnt_pt, n) != 0)
        return false;
    return path[n] == '\0' || path[n] == '/';
}

static struct mnt *mm_mi_covering(const char *path) {
    struct mnt *m, *best = NULL;
    size_t bestlen = 0;
    for (m = g_mnt; m; m = m->next) {
        size_t n = strlen(m->point);
        if (mm_under(m->point, path) && n >= bestlen) {
            best = m;
            bestlen = n;
        }
    }
    return best;
}

static struct mnt *mm_mi_exact(const char *path) {
    struct mnt *m;
    for (m = g_mnt; m; m = m->next)
        if (strcmp(m->point, path) == 0)
            return m;
    return NULL;
}

/* Number of vfsmounts traversed from the root mount to m. */
static int mm_mi_depth(struct mnt *m) {
    int d = 1, guard = 0;
    while (m && m->parent != 0 && guard++ < 256) {
        m = mm_mi_by_id(m->parent);
        if (m)
            d++;
        else
            break;
    }
    return d;
}

static unsigned long mm_flags_from_opts(const char *opts) {
    unsigned long f = 0;
    char *dup, *save = NULL, *t;
    if (!opts)
        return 0;
    dup = strdup(opts);
    if (!dup)
        return 0;
    for (t = strtok_r(dup, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        if (!strcmp(t, "ro"))
            f |= MS_RDONLY;
        else if (!strcmp(t, "nosuid"))
            f |= MS_NOSUID;
        else if (!strcmp(t, "nodev"))
            f |= MS_NODEV;
        else if (!strcmp(t, "noexec"))
            f |= MS_NOEXEC;
        else if (!strcmp(t, "noatime"))
            f |= MS_NOATIME;
        else if (!strcmp(t, "nodiratime"))
            f |= MS_NODIRATIME;
        else if (!strcmp(t, "relatime"))
            f |= MS_RELATIME;
        else if (!strcmp(t, "strictatime"))
            f |= MS_STRICTATIME;
    }
    free(dup);
    return f;
}

/* Make our mount at "target" carry the same per-mount flags as the native
 * mount that covers "ref_dir" (so ro/nosuid/... look stock). */
static void mm_mirror_flags(const char *target, const char *ref_dir) {
    struct mnt *m;
    unsigned long flags;

    if (!ref_dir)
        return;
    m = mm_mi_covering(ref_dir);
    if (!m)
        return;
    flags = mm_flags_from_opts(m->opts);
    if (!flags)
        return;
    if (mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | flags, NULL) < 0)
        mm_dbg("flag mirror on %s: %s", target, strerror(errno));
}

/* ------------------------------------------------------------------ */
/* module tree                                                         */
/* ------------------------------------------------------------------ */

enum node_type { NT_FILE, NT_DIR, NT_SYMLINK, NT_WHITEOUT };

struct node {
    char *name;
    enum node_type type;
    char *src;          /* module-provided source path             */
    bool replace;       /* directory carries trusted.overlay.opaque */
    bool skip;          /* cannot be realised                      */
    struct node *child; /* first child                             */
    struct node *next;  /* next sibling                            */
};

/* Native identity of a mountpoint, sampled before we cover it.  The kernel
 * LKM reports these values back on statfs()/stat() so the replacement looks
 * like the filesystem that used to live there. */
struct mm_meta {
    uint64_t dev;    /* kernel dev encoding: (major << 20) | minor */
    uint64_t f_type; /* statfs f_type of the covered filesystem      */
    uint32_t flags;  /* MH_REC_F_* bits that are valid               */
};

struct mm_target {
    char *path;      /* final mountpoint                            */
    struct mm_meta meta;
};

struct ctx {
    bool verbose;
    const char *source;
    char ws[PATH_MAX];
    int n_direct;
    int n_skel;
    int n_nested;
    int n_mirror;
    int n_auto;
    int max_extra;
    struct mm_target *targets; /* final paths we attached something to */
    int n_targets;
    int cap_targets;
    int *snap_ids; /* mount IDs that existed before mounting */
    int n_snap;
};

/* Parallel mount jobs share the target list and the counters; every update
 * goes through this lock. */
static pthread_mutex_t g_ctx_mu = PTHREAD_MUTEX_INITIALIZER;

enum mm_counter { MM_CNT_DIRECT, MM_CNT_NESTED, MM_CNT_SKEL, MM_CNT_MIRROR };

static void mm_count(struct ctx *c, enum mm_counter kind) {
    pthread_mutex_lock(&g_ctx_mu);
    switch (kind) {
    case MM_CNT_DIRECT:
        c->n_direct++;
        if (c->max_extra < 1)
            c->max_extra = 1;
        break;
    case MM_CNT_NESTED:
        c->n_nested++;
        if (c->max_extra < 2)
            c->max_extra = 2;
        break;
    case MM_CNT_SKEL:
        c->n_skel++;
        break;
    case MM_CNT_MIRROR:
        c->n_mirror++;
        break;
    }
    pthread_mutex_unlock(&g_ctx_mu);
}

static struct node *node_new(const char *name, enum node_type type, const char *src) {
    struct node *n = calloc(1, sizeof(*n));
    if (!n)
        return NULL;
    n->name = strdup(name);
    n->type = type;
    n->src = src ? strdup(src) : NULL;
    return n;
}

static void node_free(struct node *n) {
    while (n) {
        struct node *next = n->next;
        node_free(n->child);
        free(n->name);
        free(n->src);
        free(n);
        n = next;
    }
}

static struct node *node_find(struct node *parent, const char *name) {
    struct node *n;
    for (n = parent->child; n; n = n->next)
        if (strcmp(n->name, name) == 0)
            return n;
    return NULL;
}

static void node_append(struct node *parent, struct node *child) {
    struct node **p = &parent->child;
    while (*p)
        p = &(*p)->next;
    *p = child;
}

static struct node *node_take(struct node *parent, const char *name) {
    struct node **p = &parent->child;
    while (*p) {
        if (strcmp((*p)->name, name) == 0) {
            struct node *n = *p;
            *p = n->next;
            n->next = NULL;
            return n;
        }
        p = &(*p)->next;
    }
    return NULL;
}

static enum node_type node_type_of(const struct stat *st) {
    if (S_ISCHR(st->st_mode) && st->st_rdev == 0)
        return NT_WHITEOUT;
    if (S_ISREG(st->st_mode))
        return NT_FILE;
    if (S_ISDIR(st->st_mode))
        return NT_DIR;
    return NT_SYMLINK;
}

/* Merge one module's "system" tree into parent.  Returns true when the
 * subtree contains something that has to be mounted. */
static bool node_collect(struct node *parent, const char *moddir) {
    DIR *d;
    struct dirent *de;
    bool has = false;

    d = opendir(moddir);
    if (!d)
        return false;

    while ((de = readdir(d))) {
        struct stat st;
        enum node_type type;
        struct node *n;
        bool replace = false;
        char *src;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        src = mm_join(moddir, de->d_name);
        if (!src)
            break;
        if (lstat(src, &st) != 0) {
            free(src);
            continue;
        }
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode) &&
            !(S_ISCHR(st.st_mode) && st.st_rdev == 0)) {
            free(src);
            continue;
        }
        type = node_type_of(&st);
        if (type == NT_DIR)
            replace = mm_is_opaque(src);

        n = node_find(parent, de->d_name);
        if (!n) {
            n = node_new(de->d_name, type, src);
            if (!n) {
                free(src);
                break;
            }
            n->replace = replace;
            node_append(parent, n);
        }
        if (n->type == NT_DIR && replace)
            n->replace = true;

        /* Recurse into the *current* module's subdirectory so that several
         * modules contributing to the same directory merge correctly. */
        if (n->type == NT_DIR && type == NT_DIR) {
            if (node_collect(n, src))
                has = true;
            if (n->replace)
                has = true;
        } else {
            has = true;
        }
        free(src);
    }
    closedir(d);
    return has;
}

static struct node *mm_collect_all(void) {
    struct node *root, *system;
    DIR *d;
    struct dirent *de;
    bool has = false;

    d = opendir(MM_MODULE_DIR);
    if (!d) {
        mm_dbg("no module directory %s", MM_MODULE_DIR);
        return NULL;
    }

    root = node_new("", NT_DIR, NULL);
    system = node_new("system", NT_DIR, NULL);
    if (!root || !system) {
        node_free(root);
        node_free(system);
        closedir(d);
        return NULL;
    }

    while ((de = readdir(d))) {
        char *mod, *modsys, *disable, *skipm;
        bool is_dir = false;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        mod = mm_join(MM_MODULE_DIR, de->d_name);
        if (!mod)
            break;
        /* file_type() does not follow symlinks in the reference logic */
        {
            struct stat st;
            is_dir = lstat(mod, &st) == 0 && S_ISDIR(st.st_mode);
        }
        if (!is_dir) {
            free(mod);
            continue;
        }
        disable = mm_join(mod, "disable");
        skipm = mm_join(mod, "skip_mount");
        modsys = mm_join(mod, "system");
        if ((disable && mm_exists(disable)) || (skipm && mm_exists(skipm)) ||
            !mm_dir_exists(modsys)) {
            free(disable);
            free(skipm);
            free(modsys);
            free(mod);
            continue;
        }
        mm_dbg("collecting %s", mod);
        if (node_collect(system, modsys))
            has = true;
        free(disable);
        free(skipm);
        free(modsys);
        free(mod);
    }
    closedir(d);

    if (!has) {
        node_free(root);
        node_free(system);
        return NULL;
    }

    /* Partitions that live at /<part> while modules write to /system/<part>. */
    {
        static const struct { const char *name; bool need_symlink; } parts[] = {
            { "vendor", true }, { "system_ext", true }, { "product", true },
            { "odm", false }, { "oem", false },
        };
        size_t i;
        for (i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
            char sysrel[64];
            char *rootp, *sysp;
            struct stat st;
            bool ok;
            struct node *n;

            snprintf(sysrel, sizeof(sysrel), "system/%s", parts[i].name);
            rootp = mm_join(MM_ROOT_PREFIX, parts[i].name);
            sysp = mm_join(MM_ROOT_PREFIX, sysrel);
            ok = rootp && mm_dir_exists(rootp);
            if (ok && parts[i].need_symlink)
                ok = sysp && lstat(sysp, &st) == 0 && S_ISLNK(st.st_mode);
            n = ok ? node_take(system, parts[i].name) : NULL;
            if (n)
                node_append(root, n);
            free(rootp);
            free(sysp);
        }
    }

    node_append(root, system);
    return root;
}

/* ------------------------------------------------------------------ */
/* mount primitives                                                    */
/* ------------------------------------------------------------------ */

/* Sample the native filesystem identity a target currently exposes.  When the
 * target does not exist (a module-only entry) walk up to the nearest ancestor
 * so a new file still reports the filesystem it is created in. */
static void mm_meta_capture(struct mm_meta *m, const char *path) {
    char *cur;

    m->dev = 0;
    m->f_type = 0;
    m->flags = 0;
    if (!path || !*path)
        return;
    cur = strdup(path);
    if (!cur)
        return;

    for (;;) {
        struct statfs sf;
        struct stat st;
        bool have_sf = statfs(cur, &sf) == 0;
        bool have_st = stat(cur, &st) == 0;
        char *slash;

        if (have_sf || have_st) {
            if (have_sf) {
                m->f_type = (uint64_t)(unsigned long)sf.f_type;
                m->flags |= MH_REC_F_TYPE;
            }
            if (have_st) {
                m->dev = ((uint64_t)major(st.st_dev) << 20) |
                         (uint64_t)minor(st.st_dev);
                m->flags |= MH_REC_F_DEV;
            }
            break;
        }

        slash = strrchr(cur, '/');
        if (!slash)
            break;
        if (slash == cur) {
            if (cur[1] == '\0')
                break; /* already "/" */
            cur[1] = '\0';
        } else {
            *slash = '\0';
        }
    }
    free(cur);
}

static void mm_record(struct ctx *c, const char *target, const struct mm_meta *meta) {
    struct mm_target *t;

    pthread_mutex_lock(&g_ctx_mu);
    if (c->n_targets == c->cap_targets) {
        int cap = c->cap_targets ? c->cap_targets * 2 : 64;
        struct mm_target *p =
            realloc(c->targets, (size_t)cap * sizeof(*p));
        if (!p) {
            pthread_mutex_unlock(&g_ctx_mu);
            return;
        }
        c->targets = p;
        c->cap_targets = cap;
    }
    t = &c->targets[c->n_targets];
    t->path = strdup(target);
    if (!t->path) {
        pthread_mutex_unlock(&g_ctx_mu);
        return;
    }
    t->meta = *meta;
    c->n_targets++;
    pthread_mutex_unlock(&g_ctx_mu);
}

static void mm_targets_free(struct ctx *c) {
    int i;
    for (i = 0; i < c->n_targets; i++)
        free(c->targets[i].path);
    free(c->targets);
    c->targets = NULL;
    c->n_targets = c->cap_targets = 0;
    free(c->snap_ids);
    c->snap_ids = NULL;
    c->n_snap = 0;
}

/* Remember the mount IDs that exist before magic_mount runs (g_mnt is the
 * snapshot taken by mm_mi_load()), so the post-mount scan can tell which
 * mountinfo entries this run created. */
static void mm_snapshot_take(struct ctx *c) {
    struct mnt *m;
    int n = 0;

    free(c->snap_ids);
    c->snap_ids = NULL;
    c->n_snap = 0;

    for (m = g_mnt; m; m = m->next)
        n++;
    if (!n)
        return;
    c->snap_ids = malloc((size_t)n * sizeof(int));
    if (!c->snap_ids)
        return;
    n = 0;
    for (m = g_mnt; m; m = m->next)
        c->snap_ids[n++] = m->id;
    c->n_snap = n;
}

static bool mm_snap_has(const struct ctx *c, int id) {
    int i;
    for (i = 0; i < c->n_snap; i++)
        if (c->snap_ids[i] == id)
            return true;
    return false;
}

static bool mm_target_known(const struct ctx *c, const char *path) {
    int i;
    for (i = 0; i < c->n_targets; i++)
        if (!strcmp(c->targets[i].path, path))
            return true;
    return false;
}

static bool mm_under_target(const struct ctx *c, const char *path) {
    int i;
    for (i = 0; i < c->n_targets; i++)
        if (mm_under(c->targets[i].path, path))
            return true;
    return false;
}

/* Auto-detect the mounts this run created instead of relying only on the
 * explicit records: a mountinfo entry whose ID did not exist before is one
 * magic_mount attached, and an entry below an already recorded mountpoint is
 * a sub-mount the mount code did not record itself.  Both are published for
 * procfs hiding; only explicitly recorded paths carry dev/f_type. */
static void mm_scan_new_mounts(struct ctx *c) {
    struct mm_meta none = { 0, 0, 0 };
    struct mnt *m;

    if (mm_mi_load() < 0)
        return;
    for (m = g_mnt; m; m = m->next) {
        if (mm_snap_has(c, m->id) || mm_target_known(c, m->point))
            continue;
        if (!mm_under_target(c, m->point))
            continue;
        mm_record(c, m->point, &none);
        c->n_auto++;
    }
    if (c->n_auto)
        mm_info("auto-detected %d additional mountpoint(s)", c->n_auto);
}

static int mm_bind(const char *src, const char *dst, const char *ref_dir) {
    if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
        mm_err("bind %s -> %s: %s", src, dst, strerror(errno));
        return -1;
    }
    /* Bind mounts inherit the per-mount flags of the *source* mount (e.g.
     * nosuid from /data).  Re-apply the flags of the native mount that the
     * target covers so the result looks like a stock mount. */
    mm_mirror_flags(dst, ref_dir);
    return 0;
}

static int mm_clone_symlink(const char *src, const char *dst) {
    char target[PATH_MAX];
    ssize_t n = readlink(src, target, sizeof(target) - 1);
    if (n < 0)
        return -1;
    target[n] = '\0';
    if (symlink(target, dst) < 0)
        return -1;
    mm_copy_label(src, dst);
    return 0;
}

/* Attach a populated skeleton at "tgt".  The self-bind mount that roots the
 * skeleton was created before its children were populated, so MS_MOVE carries
 * the whole mount tree (including every file bind inside it) in one step. */
static int mm_promote(struct ctx *c, const char *ws, const char *tgt, const char *ref_dir) {
    struct mm_meta meta;

    if (!mm_exists(tgt)) {
        mm_err("cannot attach skeleton %s: target does not exist", tgt);
        return -1;
    }
    /* The native directory is still visible here: remember what it was. */
    mm_meta_capture(&meta, tgt);
#if defined(SYS_move_mount)
    if (syscall(SYS_move_mount, AT_FDCWD, ws, AT_FDCWD, tgt, 0) < 0) {
#else
    if (mount(ws, tgt, NULL, MS_MOVE, NULL) < 0) {
#endif
        mm_err("move %s -> %s: %s", ws, tgt, strerror(errno));
        return -1;
    }
    mount(NULL, tgt, NULL, MS_PRIVATE, NULL);
    mm_mirror_flags(tgt, ref_dir);
    mm_record(c, tgt, &meta);
    mm_count(c, MM_CNT_SKEL);
    return 0;
}

/* Re-create one native entry inside the skeleton (tmpfs dirs, direct file
 * binds, cloned symlinks). */
static int mm_mirror_entry(struct ctx *c, const char *tgt_dir, const char *ws_dir,
                           const char *name, const char *ref_dir);

static int mm_mirror_dir(struct ctx *c, const char *tgt_dir, const char *ws_dir,
                         const char *ref_dir) {
    DIR *d;
    struct dirent *de;
    int rc = 0;

    d = opendir(tgt_dir);
    if (!d)
        return -1;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (mm_mirror_entry(c, tgt_dir, ws_dir, de->d_name, ref_dir) < 0)
            rc = -1;
    }
    closedir(d);
    return rc;
}

static int mm_mirror_entry(struct ctx *c, const char *tgt_dir, const char *ws_dir,
                           const char *name, const char *ref_dir) {
    char *tpath = mm_join(tgt_dir, name);
    char *wpath = mm_join(ws_dir, name);
    struct stat st;
    int rc = -1;

    if (!tpath || !wpath || lstat(tpath, &st) != 0)
        goto out;

    if (S_ISREG(st.st_mode)) {
        struct mm_meta meta;

        mm_meta_capture(&meta, tpath);
        if (mm_touch(wpath) < 0) {
            mm_err("placeholder %s: %s", wpath, strerror(errno));
            goto out;
        }
        if (mm_bind(tpath, wpath, ref_dir) < 0)
            goto out;
        mm_record(c, tpath, &meta);
        mm_count(c, MM_CNT_MIRROR);
        rc = 0;
    } else if (S_ISDIR(st.st_mode)) {
        if (mm_mkdirs(wpath) < 0) {
            mm_err("mkdir %s: %s", wpath, strerror(errno));
            goto out;
        }
        mm_copy_dir_meta(tpath, wpath);
        rc = mm_mirror_dir(c, tpath, wpath, ref_dir);
    } else if (S_ISLNK(st.st_mode)) {
        rc = mm_clone_symlink(tpath, wpath) == 0 ? 0 : -1;
    }

out:
    free(tpath);
    free(wpath);
    return rc;
}

/* ------------------------------------------------------------------ */
/* parallel mount batches                                              */
/* ------------------------------------------------------------------ */

/* Mounting thousands of tiny module files is dominated by independent
 * syscalls (one bind per file, one per mirrored entry).  The tree walk stays
 * ordered - a tmpfs skeleton must exist and be rooted before anything is
 * mounted below it - but the work collected for one directory is
 * independent, so it runs on a bounded set of threads.
 *
 * The budget is process-global: a directory job that spawns its own batch
 * only gets the permits the outer level did not take, and falls back to
 * inline execution when none are left.  That bounds the total thread count
 * no matter how deep the tree is. */

#define MM_MAX_THREADS 8
#define MM_MIN_PARALLEL 4

static pthread_mutex_t g_budget_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_budget = -1; /* worker permits, initialised on first use */

static int mm_take_permits(int want) {
    int taken;

    pthread_mutex_lock(&g_budget_mu);
    if (g_budget < 0) {
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpus < 1 || cpus > MM_MAX_THREADS)
            cpus = cpus > MM_MAX_THREADS ? MM_MAX_THREADS : 1;
        g_budget = (int)cpus;
    }
    taken = want < g_budget ? want : g_budget;
    g_budget -= taken;
    pthread_mutex_unlock(&g_budget_mu);
    return taken;
}

static void mm_release_permits(int n) {
    if (n <= 0)
        return;
    pthread_mutex_lock(&g_budget_mu);
    g_budget += n;
    pthread_mutex_unlock(&g_budget_mu);
}

static int do_magic_mount(struct ctx *c, const char *tgt_base, const char *ws_base,
                          struct node *node, bool has_tmpfs);

/* One unit of work inside a directory: either a collected module sub-tree
 * (owned when it was taken out of the parent's child list) or a native entry
 * that has to be mirrored into the skeleton. */
struct mm_job {
    struct ctx *c;
    const char *tgt; /* target directory   */
    const char *ws;  /* workspace directory */
    bool has_tmpfs;
    struct node *node; /* module sub-tree, NULL for a mirror job */
    bool own;          /* node was unlinked and must be freed here */
    char *name;        /* mirror job: entry name (owned)           */
    bool mirror;
    int rc;
};

struct mm_batch {
    struct mm_job *jobs;
    int n;
    atomic_int next;
};

static void mm_job_run(struct mm_job *j) {
    if (j->mirror) {
        j->rc = mm_mirror_entry(j->c, j->tgt, j->ws, j->name, j->tgt);
    } else {
        j->rc = do_magic_mount(j->c, j->tgt, j->ws, j->node, j->has_tmpfs);
        if (j->own)
            node_free(j->node);
        j->node = NULL;
    }
}

static void *mm_worker(void *arg) {
    struct mm_batch *b = arg;
    int i;

    while ((i = atomic_fetch_add(&b->next, 1)) < b->n)
        mm_job_run(&b->jobs[i]);
    return NULL;
}

static bool mm_jobs_add(struct mm_job **jobs, int *n, int *cap,
                        const struct mm_job *job) {
    if (*n == *cap) {
        int c = *cap ? *cap * 2 : 16;
        struct mm_job *p = realloc(*jobs, (size_t)c * sizeof(*p));
        if (!p)
            return false;
        *jobs = p;
        *cap = c;
    }
    (*jobs)[(*n)++] = *job;
    return true;
}

static void mm_run_jobs(struct mm_job *jobs, int n) {
    struct mm_batch b;
    pthread_t tids[MM_MAX_THREADS];
    int threads, i;

    if (n <= 0)
        return;
    if (n < MM_MIN_PARALLEL) {
        for (i = 0; i < n; i++)
            mm_job_run(&jobs[i]);
        return;
    }

    threads = mm_take_permits(n < MM_MAX_THREADS ? n : MM_MAX_THREADS);
    if (threads < 2) {
        mm_release_permits(threads);
        for (i = 0; i < n; i++)
            mm_job_run(&jobs[i]);
        return;
    }

    b.jobs = jobs;
    b.n = n;
    atomic_init(&b.next, 0);
    for (i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], NULL, mm_worker, &b) != 0) {
            /* No thread for this slot: run the rest here, then join. */
            threads = i;
            mm_worker(&b);
            break;
        }
    }
    for (i = 0; i < threads; i++)
        pthread_join(tids[i], NULL);
    mm_release_permits(threads);
}

/* ------------------------------------------------------------------ */
/* recursive mount                                                     */
/* ------------------------------------------------------------------ */

static int do_magic_mount(struct ctx *c, const char *tgt_base, const char *ws_base,
                          struct node *node, bool has_tmpfs) {
    char *tgt = node->name[0] ? mm_join(tgt_base, node->name) : strdup(tgt_base);
    char *ws = node->name[0] ? mm_join(ws_base, node->name) : strdup(ws_base);
    int rc = 0;

    if (!tgt || !ws) {
        free(tgt);
        free(ws);
        return -1;
    }

    switch (node->type) {
    case NT_FILE:
    case NT_SYMLINK:
        if (node->type == NT_SYMLINK) {
            char *dst = has_tmpfs ? ws : tgt;
            if (has_tmpfs) {
                rc = mm_clone_symlink(node->src, dst) == 0 ? 0 : -1;
                if (rc < 0)
                    mm_err("symlink %s -> %s failed", node->src, dst);
            } else if (!mm_exists(tgt)) {
                if (mm_clone_symlink(node->src, tgt) == 0)
                    rc = 0;
            }
            break;
        }

        if (has_tmpfs) {
            struct mm_meta meta;

            mm_meta_capture(&meta, tgt);
            if (mm_touch(ws) < 0) {
                mm_err("placeholder %s: %s", ws, strerror(errno));
                rc = -1;
                break;
            }
            rc = mm_bind(node->src, ws, tgt_base);
            if (rc == 0) {
                mm_record(c, tgt, &meta);
                mm_count(c, MM_CNT_NESTED);
            }
        } else {
            struct mm_meta meta;

            if (!mm_exists(tgt)) {
                mm_err("target %s does not exist (parent should own a skeleton)", tgt);
                rc = -1;
                break;
            }
            mm_meta_capture(&meta, tgt);
            rc = mm_bind(node->src, tgt, tgt_base);
            if (rc == 0) {
                mm_record(c, tgt, &meta);
                mm_count(c, MM_CNT_DIRECT);
            }
        }
        break;

    case NT_WHITEOUT:
        /* The parent directory is forced into a skeleton by the type check
         * below, so simply omitting the entry deletes it. */
        mm_dbg("whiteout %s", tgt);
        break;

    case NT_DIR: {
        bool create_tmpfs = !has_tmpfs && node->replace && node->src;
        bool tgt_exists = node->replace ? mm_exists(tgt) : mm_dir_exists(tgt);
        const char *meta_src;
        struct mm_job *jobs = NULL;
        int n_jobs = 0, cap_jobs = 0;
        bool batch_failed = false;

        if (!has_tmpfs && !create_tmpfs) {
            struct node *ch;
            for (ch = node->child; ch; ch = ch->next) {
                char *tpath = mm_join(tgt, ch->name);
                bool need = false;
                if (ch->type == NT_SYMLINK) {
                    need = true;
                } else if (ch->type == NT_WHITEOUT) {
                    need = tpath && mm_exists(tpath);
                } else if (tpath) {
                    struct stat st;
                    if (lstat(tpath, &st) != 0) {
                        need = true;
                    } else {
                        enum node_type rt = node_type_of(&st);
                        if (rt != ch->type || rt == NT_SYMLINK)
                            need = true;
                    }
                }
                free(tpath);
                if (!need)
                    continue;
                if (!node->src) {
                    mm_err("cannot create tmpfs on %s, skipping %s", tgt, ch->name);
                    ch->skip = true;
                    continue;
                }
                create_tmpfs = true;
                break;
            }
        }

        has_tmpfs = has_tmpfs || create_tmpfs;

        if (has_tmpfs) {
            if (mm_mkdirs(ws) < 0) {
                mm_err("mkdir %s: %s", ws, strerror(errno));
                rc = -1;
                break;
            }
            meta_src = mm_exists(tgt) ? tgt : node->src;
            mm_copy_dir_meta(meta_src, ws);
        }

        if (create_tmpfs) {
            /* Root the skeleton now: children mounted below this path become
             * submounts of it and move together with it later. */
            if (mount(ws, ws, NULL, MS_BIND, NULL) < 0) {
                mm_err("self bind %s: %s", ws, strerror(errno));
                rc = -1;
                break;
            }
        }

        /* Native entries first; module-only children afterwards, exactly
         * like the reference implementation (module entries win).  The two
         * sets touch disjoint paths, so they are collected here and then
         * mounted together on the worker threads. */
        if (!node->replace && mm_dir_exists(tgt)) {
            DIR *d = opendir(tgt);
            struct dirent *de;
            if (!d) {
                mm_err("opendir %s: %s", tgt, strerror(errno));
                rc = -1;
            } else {
                while ((de = readdir(d))) {
                    struct node *ch;
                    struct mm_job job;
                    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                        continue;
                    memset(&job, 0, sizeof(job));
                    job.c = c;
                    job.tgt = tgt;
                    job.ws = ws;
                    job.has_tmpfs = has_tmpfs;
                    ch = node_take(node, de->d_name);
                    if (ch) {
                        if (ch->skip) {
                            node_free(ch);
                            continue;
                        }
                        job.node = ch;
                        job.own = true;
                    } else if (has_tmpfs) {
                        job.mirror = true;
                        job.name = strdup(de->d_name);
                        if (!job.name)
                            continue;
                    } else {
                        continue;
                    }
                    if (!mm_jobs_add(&jobs, &n_jobs, &cap_jobs, &job)) {
                        mm_job_run(&job);
                        if (job.mirror)
                            free(job.name);
                    }
                }
                closedir(d);
            }
        }

        {
            struct node *ch;
            for (ch = node->child; ch; ch = ch->next) {
                struct mm_job job;
                if (ch->skip)
                    continue;
                memset(&job, 0, sizeof(job));
                job.c = c;
                job.tgt = tgt;
                job.ws = ws;
                job.has_tmpfs = has_tmpfs;
                job.node = ch; /* still owned by node->child */
                job.own = false;
                if (!mm_jobs_add(&jobs, &n_jobs, &cap_jobs, &job)) {
                    mm_job_run(&job);
                    if (job.mirror)
                        free(job.name);
                }
            }
        }

        mm_run_jobs(jobs, n_jobs);

        {
            int i;
            for (i = 0; i < n_jobs; i++) {
                if (jobs[i].rc >= 0)
                    continue;
                if (has_tmpfs) {
                    batch_failed = true;
                } else {
                    const char *nm =
                        jobs[i].mirror ? jobs[i].name : jobs[i].node->name;
                    mm_err("child %s/%s failed", tgt, nm ? nm : "?");
                }
            }
            for (i = 0; i < n_jobs; i++)
                if (jobs[i].mirror)
                    free(jobs[i].name);
            free(jobs);
        }

        if (batch_failed)
            rc = -1;
        if (!rc && create_tmpfs)
            rc = mm_promote(c, ws, tgt, tgt_exists ? tgt : tgt_base);
        break;
    }
    }

    free(tgt);
    free(ws);
    return rc;
}

/* ------------------------------------------------------------------ */
/* private random tmpfs workspace                                      */
/* ------------------------------------------------------------------ */

static void mm_random_hex(char *out, int len) {
    unsigned char buf[32];
    size_t got = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);
        if (n > 0)
            got = (size_t)n;
    }
    if (!got) {
        unsigned int seed = (unsigned int)getpid() ^ (unsigned int)time(NULL);
        size_t i;
        srand(seed);
        for (i = 0; i < sizeof(buf); i++)
            buf[i] = (unsigned char)rand();
        got = sizeof(buf);
    }
    for (int i = 0; i < len; i++)
        out[i] = "0123456789abcdef"[buf[i % got] & 0x0f];
    out[len] = '\0';
}

static int mm_ws_create(struct ctx *c) {
    static const char *bases[] = { "/debug_ramdisk", "/sbin", "/tmp", NULL };
    size_t b;

    for (b = 0; bases[b]; b++) {
        char hex[24];
        char path[PATH_MAX];

        if (!mm_dir_exists(bases[b]))
            continue;
        mm_random_hex(hex, 16);
        if (snprintf(path, sizeof(path), "%s/mm-%s", bases[b], hex) >= (int)sizeof(path))
            continue;
        if (mkdir(path, 0700) < 0)
            continue;
        if (mount(c->source, path, "tmpfs", 0, MM_WS_SIZE) < 0) {
            mm_err("mount tmpfs on %s: %s", path, strerror(errno));
            rmdir(path);
            continue;
        }
        /* Never propagate into (or out of) the host mount namespace. */
        mount(NULL, path, NULL, MS_PRIVATE, NULL);
        snprintf(c->ws, sizeof(c->ws), "%s", path);
        mm_dbg("workspace %s", path);
        return 0;
    }
    mm_err("no usable tmpfs base directory");
    return -1;
}

static void mm_ws_destroy(struct ctx *c) {
    if (!c->ws[0])
        return;
    if (umount2(c->ws, MNT_DETACH) < 0)
        mm_dbg("detach workspace: %s", strerror(errno));
    rmdir(c->ws);
    c->ws[0] = '\0';
}

/* ------------------------------------------------------------------ */
/* final audit                                                         */
/* ------------------------------------------------------------------ */

static int mm_audit(struct ctx *c) {
    int i, j;
    int max_depth = 0;
    int stacked = 0;
    int missing = 0;

    if (mm_mi_load() < 0)
        return -1;
    for (i = 0; i < c->n_targets; i++) {
        struct mnt *m = mm_mi_exact(c->targets[i].path);
        int depth;
        if (!m) {
            missing++;
            continue;
        }
        depth = mm_mi_depth(m);
        if (depth > max_depth)
            max_depth = depth;
        for (j = 0; j < i; j++)
            if (!strcmp(c->targets[j].path, c->targets[i].path)) {
                stacked++;
                break;
            }
    }
    mm_info("audit: created=%d mounted=%d missing=%d max_vfsmount_depth=%d stacked=%d",
            c->n_targets, c->n_targets - missing, missing, max_depth, stacked);
    return 0;
}

/* ------------------------------------------------------------------ */
/* magic_hide.ko hand-off                                              */
/* ------------------------------------------------------------------ */

/* Control plane of the optional LKM: a private key type, no /proc node. */
#ifndef MM_HIDE_MODE
#define MM_HIDE_MODE MH_MODE_ALL
#endif

static struct mh_upayload *mm_payload_new(void) {
    void *p = mmap(NULL, MH_PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    return (struct mh_upayload *)p;
}

/* add_key() is deliberately cancelled by the LKM after it runs the command,
 * so ECANCELED means "handled".  The result lands in hdr.status. */
static int mm_hide_send(struct mh_upayload *pl) {
    unsigned long ptr = (unsigned long)pl;
    long r;

    errno = 0;
    r = syscall(SYS_add_key, (long)MH_KEY_TYPE, (long)MH_KEY_DESC,
                (long)&ptr, sizeof(ptr), -1L);
    if (r < 0 && errno != ECANCELED) {
        mm_dbg("magic_hide unavailable: %s", strerror(errno));
        return -1;
    }
    if (pl->hdr.status) {
        mm_dbg("magic_hide cmd %u failed: %d", pl->hdr.cmd, pl->hdr.status);
        return -1;
    }
    return 0;
}

static void mm_hide_reset(struct mh_upayload *pl) {
    memset(pl, 0, MH_PAGE_SIZE);
    pl->hdr.magic = MH_PAYLOAD_MAGIC;
    pl->hdr.version = MH_PAYLOAD_VERSION;
    pl->hdr.cmd = MH_CMD_RESET;
}

/* Publish every mountpoint together with the native f_type/st_dev we sampled
 * before covering it.  The LKM then hides the mountinfo records and answers
 * statfs()/stat() with the covered filesystem's identity. */
static void mm_hide_publish(struct ctx *c) {
    struct mh_upayload *pl;
    int i;

    if (!c->n_targets)
        return;
    pl = mm_payload_new();
    if (!pl)
        return;

    mm_hide_reset(pl);
    if (mm_hide_send(pl) < 0)
        goto out;

    i = 0;
    while (i < c->n_targets) {
        unsigned int nrec = 0, strbytes = 0, recbytes, off;
        size_t len0 = strlen(c->targets[i].path);

        if (len0 >= MH_PATH_MAX) {
            i++; /* too long for the kernel's record limit */
            continue;
        }

        while (i + (int)nrec < c->n_targets) {
            size_t len = strlen(c->targets[i + nrec].path);

            if (len >= MH_PATH_MAX)
                break;
            if ((nrec + 1) * sizeof(struct mh_urec) + strbytes + len + 1 >
                MH_BUF_MAX)
                break;
            strbytes += (unsigned int)len + 1;
            nrec++;
        }
        if (!nrec)
            break;

        memset(pl, 0, MH_PAGE_SIZE);
        pl->hdr.magic = MH_PAYLOAD_MAGIC;
        pl->hdr.version = MH_PAYLOAD_VERSION;
        pl->hdr.cmd = MH_CMD_ADD;
        pl->hdr.count = nrec;

        recbytes = nrec * (unsigned int)sizeof(struct mh_urec);
        off = recbytes;
        {
            unsigned int k;
            for (k = 0; k < nrec; k++) {
                struct mh_urec *rec =
                    (struct mh_urec *)(pl->buf + k * sizeof(*rec));
                struct mm_target *t = &c->targets[i + (int)k];
                unsigned int len = (unsigned int)strlen(t->path);

                rec->path_off = off;
                rec->path_len = len;
                rec->dev = t->meta.dev;
                rec->f_type = t->meta.f_type;
                rec->flags = t->meta.flags;
                memcpy(pl->buf + off, t->path, len + 1);
                off += len + 1;
            }
        }
        pl->hdr.data_size = off;
        if (mm_hide_send(pl) < 0)
            goto out;
        i += (int)nrec;
    }

    memset(pl, 0, MH_PAGE_SIZE);
    pl->hdr.magic = MH_PAYLOAD_MAGIC;
    pl->hdr.version = MH_PAYLOAD_VERSION;
    pl->hdr.cmd = MH_CMD_MODE;
    pl->hdr.mode = MM_HIDE_MODE;
    mm_hide_send(pl);
    mm_info("published %d mountpoints to magic_hide", c->n_targets);

out:
    munmap(pl, MH_PAGE_SIZE);
}

/* ------------------------------------------------------------------ */
/* entry points                                                        */
/* ------------------------------------------------------------------ */

static int mm_run(const char *source) {
    struct ctx c;
    struct node *root;
    int rc = 0;

    memset(&c, 0, sizeof(c));
    c.source = source && *source ? source : MM_DEFAULT_SOURCE;

    root = mm_collect_all();
    if (!root) {
        mm_info("no modules to mount, skipping");
        return 0;
    }

    if (mm_ws_create(&c) < 0) {
        node_free(root);
        return -1;
    }
    mm_dbg("workspace ready at %s", c.ws);

    mm_mi_load();
    mm_snapshot_take(&c);
    rc = do_magic_mount(&c, MM_ROOT_PREFIX, c.ws, root, false);

    mm_ws_destroy(&c);
    mm_mi_free();
    node_free(root);

    if (rc < 0)
        mm_err("magic mount failed");
    else
        mm_info("done: direct=%d skeleton=%d nested=%d mirror=%d max_extra_hops=%d",
                c.n_direct, c.n_skel, c.n_nested, c.n_mirror, c.max_extra);
    mm_audit(&c);
    mm_scan_new_mounts(&c);
    mm_hide_publish(&c);
    mm_targets_free(&c);
    return rc;
}

/* Public entry point for a thin Lua/JNI wrapper. */
int magic_mount_run(const char *mount_source) {
    return mm_run(mount_source);
}

int main(int argc, char **argv) {
    const char *source = MM_DEFAULT_SOURCE;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            g_verbose = true;
        } else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
            source = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fprintf(stderr,
                    "usage: %s [-v] [-s source]\n"
                    "  -v  verbose log\n"
                    "  -s  tmpfs source name (default \"%s\", keep it stock)\n",
                    argv[0], MM_DEFAULT_SOURCE);
            return 0;
        }
    }
    return magic_mount_run(source) == 0 ? 0 : 1;
}
