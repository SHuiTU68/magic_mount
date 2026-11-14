// SPDX-License-Identifier: GPL-2.0
/*
 * magic_hide.ko -- make magic_mount's VFS state look native.
 *
 * magic_mount attaches real bind/move mounts built from a private tmpfs
 * workspace.  The mounts themselves are indistinguishable in layout (flags are
 * mirrored, nothing is stacked), but four observations still stand out:
 *
 *   1. /proc/<pid>/mountinfo and /proc/<pid>/mounts list the new mountpoints;
 *   2. statfs()/fstatfs() report the tmpfs (or module filesystem) magic, mount
 *      flags and block accounting on a skeleton directory;
 *   3. stat()/statx()/fstat() report the tmpfs or module filesystem st_dev and
 *      f2fs inode numbers on entries the skeleton owns;
 *   4. the module and its probes are listed in /proc/modules,
 *      /sys/kernel/debug/kprobes/list, /sys/module and /proc/kallsyms;
 *   5. every caller gets the same answer, including a process that still has
 *      to use the real partition;
 *   6. getxattr("security.selinux") reports the workspace filesystem's label
 *      instead of the one the covered path had.
 *
 * Point 5 is handled outside the kretprobes: an ftrace op on the stat syscall
 * wrappers only records *who* asked (uid/pid/comm, gated by one atomic read
 * while the window is open), the module drains that table and answers with an
 * exempt-uid set that the visibility checks consult.  A kprobe cannot share a
 * function with an ftrace op on arm64, and deciding a per-process policy inside
 * the hot kretprobe would put a second policy lookup on every stat() in the
 * system; this keeps the hot path as it was.
 *
 * Points 1-3 are handled by filtering / rewriting the *completed* result, so
 * every hook is a kretprobe: a plain kprobe post_handler runs right after the
 * probed instruction is single-stepped, i.e. before the function body has
 * filled the seq_file buffer or the kstat/kstatfs structure, which makes
 * "fix up the output" impossible there.  A kretprobe entry_handler runs at
 * function entry and the return handler runs once the function is done, which
 * is exactly the point where the output can be changed:
 *
 *   - show_mountinfo()/show_vfsmnt(): entry_handler records seq_file->count,
 *     return handler parses the freshly emitted line and, if its mountpoint
 *     belongs to a magic_mount target, rewinds seq_file->count.  A directory
 *     target only hides the tmpfs skeleton stacked on it; the stock mount at
 *     that mountpoint (an overlayfs over the product partition, for example)
 *     stays listed, because a clean boot shows it too;
 *   - vfs_statfs()/vfs_getattr(): entry_handler resolves the mount root in the
 *     anchor table and copies the native f_type / dev / statfs counters into
 *     the per-instance data, return handler writes them into the caller's
 *     struct;
 *   - m_show(): entry_handler only arms when the printed module is ourselves;
 *   - show_kprobe_addr(): return handler drops lines whose
 *     "symbol+0x0" token is one of our probe points.
 *
 * Point 4's /proc/modules half is the m_show hook; the debugfs kprobes list
 * half is show_kprobe_addr.  The remaining identifiers are removed as well:
 * s_show drops the module's symbol lines from /proc/kallsyms, and
 * kernfs_fop_readdir swaps the directory actor for the duration of one
 * /sys/module listing so the kobject name never reaches userspace.  Both are
 * unconditional - they conceal the module, not a mount - and both are
 * optional, so a kernel without those symbols still loads the rest.
 *
 * Point 6 is a kretprobe on vfs_getxattr(): userspace samples the context of
 * every target before the mount exists and ships the distinct strings with the
 * table, so the answer is just a string copy from the anchor.  That fixes what
 * getfilecon()/ls -Z/stat -c %C report and makes the mount indistinguishable
 * from a stock one to anything that reads the label.  SELinux's own permission
 * checks consume the inode's in-kernel SID, which is neither readable nor
 * writable without the LSM internals; a module cannot change that half.
 *
 * The proc hooks do not depend only on the paths userspace records.  A line is
 * hidden when any of these signatures matches, so the mount table stays clean
 * even when userspace never published a record (the shipped mount core is the
 * Rust library, which does not talk to this module):
 *
 *   - the mountpoint is a private workspace (<base>/mm-<16 hex> or
 *     <base>/workdir) or lies below a recorded target;
 *   - the mountinfo root is a root-manager staging tree (/adb/modules,
 *     /data/adb/modules), which is how module file binds identify themselves;
 *   - the source token is a root-manager name (APatch/KSU/KernelSU/Magisk)
 *     or a staging path.
 *
 * Root and source are matched raw (they contain no escaped spaces), only the
 * mountpoint is unescaped.
 *
 * Cost model
 * ----------
 *  - The hot statfs/getattr kretprobes are registered only while at least one
 *    record exists and the policy is not OFF.  Their entry_handler starts with
 *    one atomic read and one fsuid check; on a miss it returns 1, which makes
 *    the kernel recycle the instance immediately (no return trampoline is
 *    installed), so unrelated stat/statfs calls only pay the breakpoint plus
 *    that early exit.
 *  - The anchor table is an RCU hash keyed by the mount root dentry (shared by
 *    every mount namespace copy), so a hit costs one hash, a linear probe and
 *    one pointer compare; no locks, no allocations.  Only the fields an
 *    anchor actually carries are written back.
 *  - The seq kretprobes only run while a proc/debugfs file is read, and their
 *    entry_handler bails out (again returning 1) as soon as the reader is not
 *    subject to the visibility policy.  mountinfo/mounts stay armed even when
 *    no record exists, because workspace mounts are matched by name.
 *
 * Control is driven from userspace through a private key type (see
 * magic_hide_uapi.h), so no control node exists to be discovered:
 *
 *     add_key("mh_sync", "sync", &page_ptr, 8, -1);
 *
 * 5.10 / 5.15 / 6.1 / 6.6 / 6.12 are handled: the kretprobe fields used here,
 * the vfs_getattr()/vfs_statfs() signatures and the list show functions are
 * identical on those trees (6.6 also keeps entry_handler/rethook semantics).
 * vfs_getxattr() is the one exception - it gained an idmap argument in 5.12 -
 * so its arguments are read through MH_XATTR_* below.
 */

#define pr_fmt(fmt) "magic_hide: " fmt

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ftrace.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/key-type.h>
#include <linux/key.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "magic_hide_uapi.h"

/*
 * GKI exports kern_path() from the VFS-internal symbol namespace.  Without the
 * import the loader rejects the whole module with
 *
 *   magic_hide: module uses symbol (kern_path) from namespace
 *   VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver, but does not
 *   import it.
 *   magic_hide: Unknown symbol kern_path (err -22)
 *
 * and no hook is ever installed.
 */
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

/*
 * One slot per published mount.  Modules that add tens of thousands of files
 * bind each of them separately, so the table has to be large enough that the
 * common case never drops a record (a 14-bit table holds 16384 mounts).  The
 * probe chain is bounded: once a table with more records than slots fills up,
 * a miss must stay a handful of instructions instead of degenerating into a
 * full-table scan on every stat() in the system.
 */
#define MH_HOT_BITS 14
#define MH_HOT_SIZE (1u << MH_HOT_BITS)
#define MH_HOT_PROBES 64u

/* Probe identifiers; used by the per-probe entry/return handlers below. */
enum mh_kind {
	MH_K_MOUNTINFO = 0,
	MH_K_VFSMNT,
	MH_K_VFSSTAT,
	MH_K_STATFS,
	MH_K_GETATTR,
	MH_K_MODULES,
	MH_K_KPROBES,
	MH_K_KALLSYMS,
};

struct mh_anchor {
	struct list_head rule; /* g_anchors, RCU walked             */
	struct list_head dead; /* reset scratch list                */
	struct path path;      /* mount root dentry, refs held      */
	bool have_path;
	char *name;            /* raw mountpoint, no escaping       */
	unsigned int name_len;
	u32 flags;
	u32 id;                /* publish order, used by the hit table */
	u32 sid;               /* index into the SID pool, or MH_SID_NONE */
	u64 dev;
	u64 f_type;
	u32 m_flags;           /* statfs().f_flags of the covered mount */
	struct mh_ustatfs st;  /* block accounting of the covered mount */
	struct mh_ukstat ks;   /* inode-level fields of the covered path */
};

/* seq_file views: remember the buffer offset at function entry. */
struct mh_seq_inst {
	struct seq_file *m;
	struct vfsmount *mnt; /* show_vfsmnt()/show_vfsstat(), for the root field */
	size_t start;
};

/* hot vfs_getattr / vfs_statfs: values resolved at entry, written at return. */
struct mh_hot_inst {
	void *out;
	u64 dev;
	u64 f_type;
	u32 flags;
	u32 m_flags;
	struct mh_ustatfs st;
	struct mh_ukstat ks;
};

/* vfs_getxattr("security.selinux"): the caller's buffer, resolved at return. */
struct mh_xattr_inst {
	void *value;
	size_t size;
	struct dentry *dentry;
};

static LIST_HEAD(g_anchors);
static DEFINE_MUTEX(g_mutex);
/*
 * Hide from every reader, including root.  Android's zygote_next native
 * isolated services keep the init mount namespace and run with root's fsuid,
 * so the old APPS default (hide only for fsuid != 0) left the whole root mount
 * table exposed to them.
 */
static enum mh_mode g_mode = MH_MODE_ALL;

/*
 * Hot lookup table.  Keyed by path->mnt->mnt_root, which is the same dentry
 * for every mount namespace copy of a mount, so app namespaces hit it too.
 */
static struct mh_anchor __rcu *g_hot[MH_HOT_SIZE];
static atomic_t g_hot_count = ATOMIC_INIT(0);
static atomic_t g_hot_type = ATOMIC_INIT(0);
static atomic_t g_hot_dev = ATOMIC_INIT(0);
static atomic_t g_hot_mflags = ATOMIC_INIT(0);
static atomic_t g_hot_stat = ATOMIC_INIT(0);
static atomic_t g_anchor_count = ATOMIC_INIT(0);

/*
 * Superblocks the anchors live on.  A getxattr("security.selinux") on any
 * other filesystem bails out before walking the parent chain, which keeps the
 * xattr hook free outside our own workspace.
 */
#define MH_SB_MAX 8
static struct super_block *g_sbs[MH_SB_MAX];
static int g_nsb;

/* Native SELinux contexts sampled by userspace before the mounts existed. */
static char *g_sid[MH_SID_MAX];
static u32 g_nsid;

#if defined(CONFIG_X86_64)
#define MH_PARM1(regs) ((regs)->di)
#define MH_PARM2(regs) ((regs)->si)
#define MH_PARM3(regs) ((regs)->dx)
#define MH_PARM4(regs) ((regs)->cx)
#define MH_PARM5(regs) ((regs)->r8)
#define MH_SET_RET(regs, val) ((regs)->ax = (unsigned long)(val))
#elif defined(CONFIG_ARM64)
#define MH_PARM1(regs) ((regs)->regs[0])
#define MH_PARM2(regs) ((regs)->regs[1])
#define MH_PARM3(regs) ((regs)->regs[2])
#define MH_PARM4(regs) ((regs)->regs[3])
#define MH_PARM5(regs) ((regs)->regs[4])
#define MH_SET_RET(regs, val) ((regs)->regs[0] = (unsigned long)(val))
#else
#error "magic_hide: unsupported architecture"
#endif

/*
 * vfs_getxattr() grew an idmap argument with idmapped mounts (5.12):
 *
 *   5.10      vfs_getxattr(dentry, name, value, size)
 *   5.15+     vfs_getxattr(idmap, dentry, name, value, size), idmap is a
 *             struct user_namespace * before 6.6 and struct mnt_idmap * after
 *
 * The 5.10 KMIs are built from their own headers, so the version check is
 * enough; it also keeps the unused extra register from being read on 5.10.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define MH_XATTR_DENTRY(regs) ((struct dentry *)MH_PARM2(regs))
#define MH_XATTR_NAME(regs) ((const char *)MH_PARM3(regs))
#define MH_XATTR_VALUE(regs) ((void *)MH_PARM4(regs))
#define MH_XATTR_SIZE(regs) ((size_t)MH_PARM5(regs))
#else
#define MH_XATTR_DENTRY(regs) ((struct dentry *)MH_PARM1(regs))
#define MH_XATTR_NAME(regs) ((const char *)MH_PARM2(regs))
#define MH_XATTR_VALUE(regs) ((void *)MH_PARM3(regs))
#define MH_XATTR_SIZE(regs) ((size_t)MH_PARM4(regs))
#endif

/* ------------------------------------------------------------------ */
/* exempt uids (process-level policy)                                  */
/* ------------------------------------------------------------------ */

/*
 * Processes that must keep seeing the real state even while hiding is on, for
 * example a system service that mmaps from a partition magic_mount replaced.
 * The set is published by the module (MH_CMD_POLICY), sorted so the hot check
 * is a binary search, and read under RCU like the anchor table.
 */
#define MH_EXEMPT_MAX 64

struct mh_uidpair {
	u32 uid;
	u32 id;
};

struct mh_uidset {
	struct rcu_head rcu;
	u32 n;					/* whole-uid exemptions */
	u32 uid[MH_EXEMPT_MAX];
	u32 np;					/* (uid, record) exemptions */
	struct mh_uidpair pair[MH_POLICY_MAX];
};

static struct mh_uidset __rcu *g_exempt;

static bool mh_uid_exempt(u32 uid)
{
	struct mh_uidset *set;
	u32 lo = 0, hi;
	bool hit = false;

	rcu_read_lock();
	set = rcu_dereference(g_exempt);
	if (set && set->n) {
		hi = set->n;
		while (lo < hi) {
			u32 mid = lo + (hi - lo) / 2;

			if (set->uid[mid] == uid) {
				hit = true;
				break;
			}
			if (set->uid[mid] < uid)
				lo = mid + 1;
			else
				hi = mid;
		}
	}
	rcu_read_unlock();
	return hit;
}

/*
 * Per-mount exemption: this caller keeps the native view of one covered mount
 * while every other path stays hidden.  Being a positive match (it is only
 * asked after the hot lookup already resolved an anchor), it does not add a
 * second lookup to unrelated stat calls.
 */
static bool mh_anchor_exempt(u32 id)
{
	struct mh_uidset *set;
	u64 key;
	u32 lo = 0, hi;
	bool hit = false;

	key = ((u64)(u32)current_fsuid().val << 32) | id;
	rcu_read_lock();
	set = rcu_dereference(g_exempt);
	if (set && set->np) {
		hi = set->np;
		while (lo < hi) {
			u32 mid = lo + (hi - lo) / 2;
			u64 k = ((u64)set->pair[mid].uid << 32) | set->pair[mid].id;

			if (k == key) {
				hit = true;
				break;
			}
			if (k < key)
				lo = mid + 1;
			else
				hi = mid;
		}
	}
	rcu_read_unlock();
	return hit;
}

/* Called with g_mutex held. */
static int mh_set_policy(const struct mh_upolicy *in, u32 n)
{
	struct mh_uidset *set, *old;
	u32 i, j, nu = 0, np = 0;

	if (n > MH_POLICY_MAX)
		return -EINVAL;

	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return -ENOMEM;

	for (i = 0; i < n; i++) {
		if (in[i].id == MH_EXEMPT_ANY) {
			if (nu < MH_EXEMPT_MAX)
				set->uid[nu++] = in[i].uid;
		} else if (np < MH_POLICY_MAX) {
			set->pair[np].uid = in[i].uid;
			set->pair[np].id = in[i].id;
			np++;
		}
	}

	/* insertion sort; both arrays are small and written once per policy */
	for (i = 1; i < nu; i++) {
		u32 v = set->uid[i];

		for (j = i; j > 0 && set->uid[j - 1] > v; j--)
			set->uid[j] = set->uid[j - 1];
		set->uid[j] = v;
	}
	for (i = 1; i < np; i++) {
		struct mh_uidpair v = set->pair[i];

		for (j = i; j > 0; j--) {
			struct mh_uidpair *p = &set->pair[j - 1];

			if (p->uid < v.uid ||
			    (p->uid == v.uid && p->id <= v.id))
				break;
			set->pair[j] = *p;
		}
		set->pair[j] = v;
	}

	set->n = nu;
	set->np = np;
	old = rcu_dereference_protected(g_exempt, lockdep_is_held(&g_mutex));
	rcu_assign_pointer(g_exempt, set);
	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

static bool mh_hide_for_current(void)
{
	enum mh_mode mode = READ_ONCE(g_mode);
	u32 uid;

	if (mode == MH_MODE_OFF)
		return false;
	uid = (u32)current_fsuid().val;
	if (mode == MH_MODE_APPS && uid == 0)
		return false;
	return !mh_uid_exempt(uid);
}

/* ------------------------------------------------------------------ */
/* caller observation (ftrace, not kprobe)                             */
/* ------------------------------------------------------------------ */

/*
 * The kretprobes below answer "what should this call return".  They cannot
 * answer "who is asking" without deciding inside the kprobe, and a kprobe
 * cannot be attached to a function that ftrace already patches on arm64.  The
 * caller identity therefore comes from a second, independent hook: an ftrace
 * op on the syscall wrappers, which is registered at boot (addresses are
 * resolved by lkm/loader from /proc/kallsyms and passed as module parameters)
 * and records uid/pid/comm per syscall into a small direct-mapped table.
 *
 * The module drains that table through MH_CMD_EVENTS and answers with
 * MH_CMD_POLICY, so the exemption list is decided in userspace with the actual
 * process list in hand, not guessed inside the kernel.
 */
/*
 * A hook is needed that answers "who is asking" without deciding the return
 * value.  ftrace would be the natural choice, but this DDK header snapshot
 * defines neither CONFIG_DYNAMIC_FTRACE nor CONFIG_FUNCTION_TRACER, and without
 * them <linux/ftrace.h> only forward-declares struct ftrace_ops -- the observer
 * cannot be compiled there at all.  The four syscall wrappers are therefore
 * covered by plain kprobes, whose addresses userspace resolves from kallsyms
 * (the wrappers are not reachable by symbol name on arm64).  Only the entry is
 * probed and only during the boot window, then the probes are torn down.
 */
#define MH_HAVE_FTRACE 1

MODULE_INFO(mh_ftrace_cfg,
	    "dft=" __stringify(IS_ENABLED(CONFIG_DYNAMIC_FTRACE))
	    " ft=" __stringify(IS_ENABLED(CONFIG_FUNCTION_TRACER)));

#if MH_HAVE_FTRACE

static unsigned long g_ft_ip[4];
module_param_named(addr_statx, g_ft_ip[0], ulong, 0);
module_param_named(addr_newfstatat, g_ft_ip[1], ulong, 0);
module_param_named(addr_statfs, g_ft_ip[2], ulong, 0);
module_param_named(addr_fstatfs, g_ft_ip[3], ulong, 0);

struct mh_ev_slot {
	u32 uid;
	u32 pid;
	u32 op;
	atomic_t count;
	char comm[MH_COMM_LEN];
};

static struct mh_ev_slot g_ev[MH_EV_MAX];
static atomic_t g_ev_on = ATOMIC_INIT(0);
static atomic_t g_ft_calls = ATOMIC_INIT(0);
static atomic_t g_ft_matched = ATOMIC_INIT(0);
static bool g_ft_filtered;
static bool g_ft_armed;
static struct kprobe g_ev_kp[4];
static bool g_ev_live[4];

/*
 * Called once per published mount table (MH_CMD_RESET), not on every
 * enable/disable.  Re-arming the probes must not touch the totals: the report
 * path re-sends the addresses and re-enables, and a reset there made a boot
 * with 28 recorded callers report "matched=false calls=0".
 */
static void mh_ev_reset(void)
{
	atomic_set(&g_ft_calls, 0);
	atomic_set(&g_ft_matched, 0);
}

static void mh_ft_hit(unsigned long ip)
{
	u32 uid = (u32)current_fsuid().val;
	struct mh_ev_slot *s = &g_ev[(uid * 2654435761u) % MH_EV_MAX];
	u32 op;

	for (op = 0; op < 4; op++) {
		if (g_ft_ip[op] == ip)
			break;
	}
	if (op == 4)
		return;
	atomic_set(&g_ft_matched, 1);

	/*
	 * uid 0 is a valid key, so "empty" is count == 0, not uid == 0.  A slot
	 * cleared by a dump is re-initialised on its next hit.
	 */
	if (READ_ONCE(s->uid) != uid || !atomic_read(&s->count)) {
		WRITE_ONCE(s->pid, 0);
		atomic_set(&s->count, 0);
		memset(s->comm, 0, sizeof(s->comm));
		strscpy(s->comm, current->comm, sizeof(s->comm));
		WRITE_ONCE(s->uid, uid);
	}
	WRITE_ONCE(s->pid, current->pid);
	WRITE_ONCE(s->op, op);
	atomic_inc(&s->count);
}

static int mh_ev_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)regs;
	if (!atomic_read(&g_ev_on))
		return 0;
	atomic_inc(&g_ft_calls);
	mh_ft_hit((unsigned long)p->addr);
	return 0;
}

static bool mh_ft_have_params(void)
{
	return g_ft_ip[0] || g_ft_ip[1] || g_ft_ip[2] || g_ft_ip[3];
}

static void mh_ft_register(void)
{
	int i, armed = 0;

	if (g_ft_armed)
		return;
	for (i = 0; i < 4; i++) {
		memset(&g_ev_kp[i], 0, sizeof(g_ev_kp[i]));
		if (!g_ft_ip[i])
			continue;
		g_ev_kp[i].pre_handler = mh_ev_pre;
		g_ev_kp[i].addr = (kprobe_opcode_t *)g_ft_ip[i];
		if (register_kprobe(&g_ev_kp[i]))
			pr_debug("cannot probe syscall %d\n", i);
		else {
			g_ev_live[i] = true;
			armed++;
		}
	}
	if (!armed)
		return;
	g_ft_filtered = true;
	g_ft_armed = true;
}

/* Drops every entry probe once the boot window is over. */
static void mh_ft_unregister(void)
{
	int i;

	atomic_set(&g_ev_on, 0);
	if (!g_ft_armed)
		return;
	for (i = 0; i < 4; i++) {
		if (g_ev_live[i]) {
			unregister_kprobe(&g_ev_kp[i]);
			g_ev_live[i] = false;
		}
	}
	g_ft_filtered = false;
	g_ft_armed = false;
}

/*
 * Addresses normally arrive as module parameters, but a load through a wrapper
 * that drops the argument string leaves them zero and the observer silently
 * dead.  Userspace already knows the values (it read kallsyms), so it can hand
 * them over the key channel at any time instead.
 */
static int mh_set_addrs(const mh_u64 *in, mh_u32 n)
{
	mh_u64 ips[4] = { 0 };
	u32 i;

	if (n < 1 || n > 4)
		return -EINVAL;
	for (i = 0; i < n; i++)
		ips[i] = in[i];

	/*
	 * The module re-sends the same four addresses whenever it re-arms the
	 * observer.  Tearing the probes down for an identical set would close and
	 * reopen the drain window for no reason.
	 */
	if (n == 4 && mh_ft_have_params()) {
		for (i = 0; i < 4; i++)
			if (g_ft_ip[i] != (unsigned long)ips[i])
				break;
		if (i == 4)
			return 0;
	}

	mh_ft_unregister();
	for (i = 0; i < 4; i++)
		g_ft_ip[i] = (unsigned long)ips[i];

	return (g_ft_ip[0] || g_ft_ip[1] || g_ft_ip[2] || g_ft_ip[3]) ? 0 : -EINVAL;
}

static u32 mh_events_dump(struct mh_upayload *pl, bool on)
{
	struct mh_uevent *out = (struct mh_uevent *)pl->buf;
	u32 i, n = 0;

	if (on) {
		mh_ft_register();
		atomic_set(&g_ev_on, 1);
	} else {
		mh_ft_unregister();
	}

	for (i = 0; i < MH_EV_MAX; i++) {
		struct mh_ev_slot *s = &g_ev[i];
		int cnt = atomic_read(&s->count);

		if (!cnt)
			continue;
		out[n].uid = READ_ONCE(s->uid);
		out[n].pid = READ_ONCE(s->pid);
		out[n].op = READ_ONCE(s->op);
		out[n].count = (u32)cnt;
		memcpy(out[n].comm, s->comm, MH_COMM_LEN);
		atomic_set(&s->count, 0);
		n++;
	}

	/*
	 * Diagnostics for the module: bit0 armed, bit1 filter installed, bit2
	 * addresses received, bit3 this call was the enabling one, bit4 at least
	 * one callback matched an address, bit5 the ftrace API exists here.
	 * reserved carries the number of callbacks entered, which separates
	 * "never called" from "called with unexpected ip".
	 */
	pl->hdr.mode = (g_ft_armed ? 1u : 0u) | (g_ft_filtered ? 2u : 0u) |
		       (mh_ft_have_params() ? 4u : 0u) | (on ? 8u : 0u) |
		       (atomic_read(&g_ft_matched) ? 16u : 0u) |
		       (MH_HAVE_FTRACE ? 32u : 0u);
	pl->hdr.reserved = (u32)atomic_read(&g_ft_calls);
	return n;
}

#else /* CONFIG_DYNAMIC_FTRACE not visible to this build */

static u32 mh_events_dump(struct mh_upayload *pl, bool on)
{
	(void)on;
	pl->hdr.mode = 0; /* observer not compiled in */
	pl->hdr.reserved = 0;
	return 0;
}

static void mh_ev_reset(void)
{
}

static void mh_ft_unregister(void)
{
}

static int mh_set_addrs(const mh_u64 *in, mh_u32 n)
{
	(void)in;
	(void)n;
	return -EOPNOTSUPP;
}

static bool mh_ft_have_params(void)
{
	return false;
}

#endif /* MH_HAVE_FTRACE */

/*
 * Who touched a covered mount.  Unlike the syscall observer above, this needs no
 * probes of its own: it is incremented in the hot path only after a lookup has
 * already matched a published record, so it answers "who looked at the thing we
 * are hiding" instead of "who called stat".  The table is a fixed 32 buckets of
 * (uid, record id), which fits in one page together with its header.
 */
static DEFINE_SPINLOCK(g_hit_mu);
static atomic_t g_hit_on = ATOMIC_INIT(0);
static struct mh_uhit g_hits[MH_HIT_MAX];

static void mh_hit_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&g_hit_mu, flags);
	memset(g_hits, 0, sizeof(g_hits));
	spin_unlock_irqrestore(&g_hit_mu, flags);
}

static void mh_hit_record(u32 id)
{
	u32 uid = (u32)__kuid_val(current_fsuid());
	unsigned long flags;
	int i, slot = -1;

	if (!atomic_read(&g_hit_on))
		return;

	spin_lock_irqsave(&g_hit_mu, flags);
	for (i = 0; i < MH_HIT_MAX; i++) {
		if (!g_hits[i].count) {
			if (slot < 0)
				slot = i;
			continue;
		}
		if (g_hits[i].uid == uid && g_hits[i].id == id) {
			g_hits[i].count++;
			spin_unlock_irqrestore(&g_hit_mu, flags);
			return;
		}
	}
	if (slot < 0) {
		/* Full: evict the least seen bucket so a noisy caller cannot
		 * crowd out the rare one we care about. */
		u64 min = ~0ull;

		for (i = 0; i < MH_HIT_MAX; i++) {
			if (g_hits[i].count < min) {
				min = g_hits[i].count;
				slot = i;
			}
		}
	}
	g_hits[slot].uid = uid;
	g_hits[slot].id = id;
	g_hits[slot].count = 1;
	memcpy(g_hits[slot].comm, current->comm, MH_COMM_LEN);
	g_hits[slot].comm[MH_COMM_LEN - 1] = 0;
	spin_unlock_irqrestore(&g_hit_mu, flags);
}

static u32 mh_hits_dump(struct mh_upayload *pl, bool on)
{
	struct mh_uhit *out = (struct mh_uhit *)pl->buf;
	unsigned long flags;
	u32 i, n = 0;

	atomic_set(&g_hit_on, on ? 1 : 0);

	spin_lock_irqsave(&g_hit_mu, flags);
	for (i = 0; i < MH_HIT_MAX; i++) {
		if (!g_hits[i].count)
			continue;
		out[n++] = g_hits[i];
		memset(&g_hits[i], 0, sizeof(g_hits[i]));
	}
	spin_unlock_irqrestore(&g_hit_mu, flags);
	return n;
}

/* ------------------------------------------------------------------ */
/* anchor table                                                        */
/* ------------------------------------------------------------------ */

static unsigned int mh_slot(const struct dentry *d, unsigned int probe)
{
	return ((unsigned int)hash_ptr((void *)d, MH_HOT_BITS) + probe) &
	       (MH_HOT_SIZE - 1);
}

/* Must be called with rcu_read_lock() held. */
static struct mh_anchor *mh_hot_lookup_dentry(const struct dentry *key)
{
	unsigned int i;

	if (!key || !atomic_read(&g_hot_count))
		return NULL;

	for (i = 0; i < MH_HOT_PROBES; i++) {
		struct mh_anchor *a = rcu_dereference(g_hot[mh_slot(key, i)]);

		if (!a)
			return NULL;
		if (a->path.dentry == key)
			return a;
	}
	return NULL;
}

/* Must be called with rcu_read_lock() held. */
static struct mh_anchor *mh_hot_lookup(const struct vfsmount *mnt)
{
	return mh_hot_lookup_dentry(READ_ONCE(mnt->mnt_root));
}

/* Called with g_mutex held. */
static int mh_hot_insert(struct mh_anchor *a)
{
	unsigned int i;

	for (i = 0; i < MH_HOT_PROBES; i++) {
		unsigned int s = mh_slot(a->path.dentry, i);

		if (!rcu_dereference_protected(g_hot[s], 1)) {
			rcu_assign_pointer(g_hot[s], a);
			atomic_inc(&g_hot_count);
			if (a->flags & MH_REC_F_TYPE)
				atomic_inc(&g_hot_type);
			if (a->flags & MH_REC_F_DEV)
				atomic_inc(&g_hot_dev);
			if (a->flags & MH_REC_F_MFLAGS)
				atomic_inc(&g_hot_mflags);
			if (a->flags & MH_REC_F_STAT)
				atomic_inc(&g_hot_stat);
			return 0;
		}
	}
	return -ENOSPC;
}

static void mh_hot_register(void);

/* Called with g_mutex held. */
static void mh_sb_remember(struct super_block *sb)
{
	int i;

	if (!sb)
		return;
	for (i = 0; i < g_nsb; i++)
		if (g_sbs[i] == sb)
			return;
	if (g_nsb < MH_SB_MAX)
		WRITE_ONCE(g_sbs[g_nsb++], sb);
}

static bool mh_sb_known(const struct super_block *sb)
{
	int i;

	if (!sb)
		return false;
	for (i = 0; i < READ_ONCE(g_nsb); i++)
		if (READ_ONCE(g_sbs[i]) == sb)
			return true;
	return false;
}

static void mh_sid_clear(void)
{
	u32 i;

	for (i = 0; i < g_nsid; i++) {
		kfree(g_sid[i]);
		g_sid[i] = NULL;
	}
	WRITE_ONCE(g_nsid, 0);
}

/*
 * `n` NUL-terminated contexts packed into buf.  Called from ->preparse() with
 * g_mutex held; the xattr probe is not registered yet at that point, so no
 * reader can race the free.
 */
static int mh_sid_set(const char *buf, u32 n, u32 size)
{
	u32 i, off = 0;

	if (n > MH_SID_MAX)
		return -EINVAL;
	mh_sid_clear();
	for (i = 0; i < n; i++) {
		size_t left = (size > off) ? size - off : 0;
		const char *s = buf + off;
		size_t len;

		if (!left)
			goto bad;
		len = strnlen(s, left);
		if (len >= left || len >= MH_SID_LEN)
			goto bad;
		g_sid[i] = kstrndup(s, len, GFP_KERNEL);
		if (!g_sid[i])
			goto bad;
		WRITE_ONCE(g_nsid, i + 1);
		off += len + 1;
	}
	return 0;
bad:
	mh_sid_clear();
	return -EINVAL;
}

/* Called with g_mutex held. */
static void mh_hot_clear(void)
{
	unsigned int i;

	for (i = 0; i < MH_HOT_SIZE; i++)
		rcu_assign_pointer(g_hot[i], NULL);
	atomic_set(&g_hot_count, 0);
	atomic_set(&g_hot_type, 0);
	atomic_set(&g_hot_dev, 0);
	atomic_set(&g_hot_mflags, 0);
	atomic_set(&g_hot_stat, 0);
}

/* One parsed /proc mount line: what it points at and what it is made of. */
struct mh_line {
	char point[MH_PATH_MAX];
	const char *fstype;
	size_t fstype_len;
	const char *root;
	size_t root_len;
	const char *source;
	size_t source_len;
	bool have_point;
};

/*
 * The recorded name that covers `path`.  A mountpoint is hidden when it
 * equals a recorded target or lies below one: magic_mount replaces whole
 * directories, so any sub-mount attached inside a replaced directory belongs
 * to the same workspace.
 */
static struct mh_anchor *mh_name_match(const char *path, size_t len)
{
	struct mh_anchor *a, *best = NULL;

	if (!len)
		return NULL;

	list_for_each_entry_rcu(a, &g_anchors, rule) {
		if (a->name_len > len || memcmp(a->name, path, a->name_len))
			continue;
		if (!(a->name_len == len || path[a->name_len] == '/'))
			continue;
		/*
		 * The longest match wins: a module file record has to hide its own
		 * bind even though the directory record above it also matches.
		 */
		if (!best || a->name_len > best->name_len)
			best = a;
	}
	return best;
}

/*
 * Does `a` hide this proc line?  A file record describes a bind of a module
 * file, which has no stock counterpart, so the line goes away.  A directory
 * record instead sits on an existing mountpoint: magic_mount stacks a tmpfs
 * skeleton there while the stock mount beneath it (overlayfs on
 * /product/overlay, for example) is part of a clean boot.  Hiding that stock
 * line would make the mount table differ from stock, so only the tmpfs line
 * is dropped.
 */
static bool mh_record_hides(const struct mh_anchor *a, const struct mh_line *l)
{
	/* A mount attached below a target is one of our mirrors or binds. */
	if (a->name_len != strlen(l->point))
		return true;
	if (!a->have_path || !d_is_dir(a->path.dentry))
		return true;
	if (!l->fstype || !l->fstype_len)
		return true;
	return l->fstype_len == 5 && !memcmp(l->fstype, "tmpfs", 5);
}

static void mh_anchor_free(struct mh_anchor *a)
{
	if (a->have_path)
		path_put(&a->path);
	kfree(a->name);
	kfree(a);
}

/*
 * Drop every published record.  Runs from ->preparse(), i.e. process context,
 * so synchronize_rcu() and path_put() may sleep here.
 */
static void mh_records_reset(void)
{
	struct mh_anchor *a, *tmp;
	LIST_HEAD(dead_list);

	mutex_lock(&g_mutex);
	list_for_each_entry_safe(a, tmp, &g_anchors, rule) {
		list_del_rcu(&a->rule);
		list_add_tail(&a->dead, &dead_list);
	}
	mh_hot_clear();
	g_nsb = 0;
	mh_sid_clear();
	atomic_set(&g_anchor_count, 0);
	mutex_unlock(&g_mutex);

	/* Record ids restart at 0, so stale hit buckets would point at the
	 * wrong path after a republish. */
	mh_hit_clear();
	mh_ev_reset();

	synchronize_rcu();

	list_for_each_entry_safe(a, tmp, &dead_list, dead) {
		list_del(&a->dead);
		mh_anchor_free(a);
	}
}

/*
 * Rebind the published identity to the mounts that exist right now.
 *
 * The hot table is keyed by the root dentry of each covered mount, which is
 * what makes a lookup a single hash probe.  A dentry is only valid for one
 * mount instance though: if anything mounts over a target again (a root
 * manager remounting a partition, a module installed later, a bind redone),
 * the new mount has a fresh root dentry and every published record silently
 * stops matching.  Re-resolving the recorded paths repairs that without
 * touching the sampled identity (dev, f_type, inode), so a late mount is
 * handled the same way as one that existed at publish time.
 *
 * Runs from ->preparse(), i.e. process context, so kern_path() may sleep.
 */
static int mh_records_refresh(void)
{
	struct mh_anchor *a;
	int ret = 0;

	mutex_lock(&g_mutex);
	mh_hot_clear();
	list_for_each_entry(a, &g_anchors, rule) {
		struct path p;

		/* procfs-only record: there is no mount to bind to. */
		if (!a->flags)
			continue;
		/* Path gone: keep the old dentry so nothing regresses. */
		if (kern_path(a->name, LOOKUP_FOLLOW, &p)) {
			pr_debug("magic_hide: cannot re-resolve %s\n", a->name);
			if (a->have_path && mh_hot_insert(a) < 0)
				ret = -ENOSPC;
			continue;
		}
		if (a->have_path)
			path_put(&a->path);
		a->path = p;
		a->have_path = true;
		if (mh_hot_insert(a) < 0) {
			path_put(&a->path);
			a->have_path = false;
			ret = -ENOSPC;
		}
	}
	mutex_unlock(&g_mutex);

	mh_hot_register();
	return ret;
}

static int mh_records_add(const char *name, unsigned int len, u32 flags,
			  u64 dev, u64 f_type, u32 m_flags,
			  const struct mh_ustatfs *st,
			  const struct mh_ukstat *ks, u32 sid)
{
	struct mh_anchor *a;

	if (!len || len >= MH_PATH_MAX || name[0] != '/')
		return -EINVAL;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;
	INIT_LIST_HEAD(&a->rule);
	INIT_LIST_HEAD(&a->dead);
	a->name = kstrndup(name, len, GFP_KERNEL);
	if (!a->name) {
		kfree(a);
		return -ENOMEM;
	}
	a->name_len = len;
	a->flags = flags & (MH_REC_F_TYPE | MH_REC_F_DEV | MH_REC_F_MFLAGS |
			    MH_REC_F_STAT | MH_REC_F_INO | MH_REC_F_DSIZE);
	a->dev = dev;
	a->f_type = f_type;
	a->m_flags = m_flags;
	if (st)
		a->st = *st;
	if (ks)
		a->ks = *ks;
	a->sid = sid < READ_ONCE(g_nsid) ? sid : MH_SID_NONE;
	if (kern_path(a->name, LOOKUP_FOLLOW, &a->path) == 0)
		a->have_path = true;

	mutex_lock(&g_mutex);
	mh_sb_remember(a->have_path ? a->path.dentry->d_sb : NULL);
	if (!a->have_path || !a->flags || mh_hot_insert(a) < 0)
		a->flags = 0; /* procfs hiding only */
	a->id = (u32)atomic_read(&g_anchor_count);
	list_add_tail_rcu(&a->rule, &g_anchors);
	atomic_inc(&g_anchor_count);
	mutex_unlock(&g_mutex);
	return 0;
}

/* ------------------------------------------------------------------ */
/* procfs record parsing                                               */
/* ------------------------------------------------------------------ */

static bool mh_copy_unescaped(const char *src, size_t n, char *dst,
			      size_t dstsz)
{
	size_t i = 0, o = 0;

	while (i < n) {
		char c = src[i];

		if (c == '\\' && i + 3 < n &&
		    src[i + 1] >= '0' && src[i + 1] <= '7' &&
		    src[i + 2] >= '0' && src[i + 2] <= '7' &&
		    src[i + 3] >= '0' && src[i + 3] <= '7') {
			c = (char)((src[i + 1] - '0') * 64 +
				   (src[i + 2] - '0') * 8 +
				   (src[i + 3] - '0'));
			i += 4;
		} else {
			i++;
		}
		if (o + 1 >= dstsz)
			return false;
		dst[o++] = c;
	}
	if (!o)
		return false;
	dst[o] = '\0';
	return true;
}

/*
 * Embedded spaces/tabs/newlines/backslashes are octal escaped by seq_escape(),
 * so a line can be split on single spaces; only the mountpoint is unescaped.
 */
static bool mh_next_token(const char *buf, size_t len, size_t *pos,
			  const char **tok, size_t *toklen)
{
	size_t i = *pos;

	while (i < len && buf[i] == ' ')
		i++;
	if (i >= len || buf[i] == '\n') {
		*pos = i;
		return false;
	}

	*tok = buf + i;
	while (i < len && buf[i] != ' ' && buf[i] != '\n')
		i++;
	*toklen = (size_t)(buf + i - *tok);
	*pos = i;
	return true;
}

/* "id parent dev root mountpoint opts... - fstype source superopts" */
static bool mh_parse_mountinfo(const char *buf, size_t len, struct mh_line *l)
{
	size_t pos = 0, tlen;
	const char *tok;
	unsigned int field = 0;
	unsigned int tail = 0;

	memset(l, 0, sizeof(*l));
	while (mh_next_token(buf, len, &pos, &tok, &tlen)) {
		if (tail) {
			/* The fstype comes first, the source token second. */
			if (tail == 1) {
				l->fstype = tok;
				l->fstype_len = tlen;
			} else if (tail == 2) {
				l->source = tok;
				l->source_len = tlen;
			}
			tail++;
			continue;
		}
		if (tlen == 1 && tok[0] == '-') {
			tail = 1; /* next token is the fstype */
			continue;
		}
		if (field == 3) {
			l->root = tok;
			l->root_len = tlen;
		} else if (field == 4) {
			l->have_point = mh_copy_unescaped(tok, tlen, l->point,
							  sizeof(l->point));
		}
		field++;
	}
	return l->have_point;
}

/* "source mountpoint fstype opts 0 0" */
static bool mh_parse_vfsmnt(const char *buf, size_t len, struct mh_line *l)
{
	size_t pos = 0, tlen;
	const char *tok;
	unsigned int field = 0;

	memset(l, 0, sizeof(*l));
	while (mh_next_token(buf, len, &pos, &tok, &tlen)) {
		if (field == 0) {
			l->source = tok;
			l->source_len = tlen;
		} else if (field == 1) {
			l->have_point = mh_copy_unescaped(tok, tlen, l->point,
							  sizeof(l->point));
		} else if (field == 2) {
			l->fstype = tok;
			l->fstype_len = tlen;
		}
		field++;
	}
	return l->have_point;
}

/*
 * /proc/<pid>/mountstats lines are prose, not the mountinfo column layout:
 *
 *   device <dev> mounted on <point> with fstype <type> <opts> <numbers>
 *
 * So take the token after "device" as the source and the token after the
 * "mounted on" pair as the mountpoint.  The device name itself may contain
 * spaces, which is why the columns are not simply counted.
 */
static bool mh_parse_vfsstat(const char *buf, size_t len, struct mh_line *l)
{
	size_t pos = 0, tlen;
	const char *tok;
	bool want_dev = false, want_fstype = false;
	unsigned int state = 0; /* 0 idle, 1 after "mounted", 2 after "on" */

	memset(l, 0, sizeof(*l));
	while (mh_next_token(buf, len, &pos, &tok, &tlen)) {
		if (state == 2) {
			l->have_point = mh_copy_unescaped(tok, tlen, l->point,
							  sizeof(l->point));
			state = 0;
			continue;
		}
		if (state == 1) {
			if (tlen == 2 && !memcmp(tok, "on", 2)) {
				state = 2;
				continue;
			}
			state = 0;
		}
		if (want_dev) {
			l->source = tok;
			l->source_len = tlen;
			want_dev = false;
			continue;
		}
		if (want_fstype) {
			l->fstype = tok;
			l->fstype_len = tlen;
			want_fstype = false;
			continue;
		}
		if (tlen == 6 && !memcmp(tok, "device", 6)) {
			want_dev = true;
			continue;
		}
		if (tlen == 6 && !memcmp(tok, "fstype", 6)) {
			want_fstype = true;
			continue;
		}
		if (tlen == 7 && !memcmp(tok, "mounted", 7))
			state = 1;
	}
	return l->have_point;
}

/* Root-manager staging trees that module file binds are rooted in. */
static bool mh_staging_path(const char *s, size_t n)
{
	static const char *const prefixes[] = {
		"/adb/modules", "/data/adb/modules",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
		size_t pl = strlen(prefixes[i]);

		if (n < pl || memcmp(s, prefixes[i], pl))
			continue;
		if (n == pl || s[pl] == '/')
			return true;
	}
	return false;
}

/* The tmpfs source string a root manager passes to its mount helper. */
static bool mh_source_token(const char *s, size_t n)
{
	static const char *const names[] = {
		"APatch", "KSU", "KernelSU", "Magisk", "magisk", "magic_mount",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (n == strlen(names[i]) && !memcmp(s, names[i], n))
			return true;
	return false;
}

static bool mh_is_hex(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

/*
 * The C core mounts its private tmpfs workspace at <base>/mm-<16 hex>; the
 * Rust core used by the shipped Lua module mounts <base>/workdir.  Both bases
 * are /debug_ramdisk, /sbin or /tmp.  The workspace is detached and removed on
 * success, but a concurrent reader or an interrupted run can still expose the
 * workspace (and every sub-mount inside it), so those names are hidden by
 * pattern instead of through a userspace record.
 */
static bool mh_ws_path_n(const char *path, size_t n)
{
	static const char *const bases[] = {
		"/debug_ramdisk/mm-", "/sbin/mm-", "/tmp/mm-",
	};
	static const char *const dirs[] = {
		"/debug_ramdisk/workdir", "/sbin/workdir", "/tmp/workdir",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		size_t dl = strlen(dirs[i]);

		if (n < dl || memcmp(path, dirs[i], dl))
			continue;
		if (n == dl || path[dl] == '/')
			return true;
	}

	for (i = 0; i < ARRAY_SIZE(bases); i++) {
		size_t bl = strlen(bases[i]);
		const char *p;
		unsigned int j;

		if (n < bl || memcmp(path, bases[i], bl))
			continue;
		p = path + bl;
		if (n < bl + 16)
			continue;
		for (j = 0; j < 16; j++)
			if (!mh_is_hex(p[j]))
				break;
		if (j != 16)
			continue;
		if (bl + 16 == n || p[16] == '/')
			return true;
	}
	return false;
}

/*
 * Rebuild the mount-root string mountinfo prints: "/" followed by the path
 * from the superblock root to the mount root.  /proc/mounts has no such
 * column, but its hook receives the mount object.  Returns 0 when the walk
 * does not reach the superblock root or the path does not fit.
 */
static size_t mh_mount_root(struct vfsmount *mnt, char *buf, size_t buflen)
{
	struct dentry *d, *root;
	size_t len = 0;
	unsigned int depth = 32;

	if (!mnt || !mnt->mnt_root || !mnt->mnt_sb || !mnt->mnt_sb->s_root)
		return 0;
	d = mnt->mnt_root;
	root = mnt->mnt_sb->s_root;
	while (d != root) {
		size_t nl;

		if (!depth-- || IS_ROOT(d))
			return 0;
		nl = d->d_name.len;
		if (len + nl + 1 >= buflen)
			return 0;
		/* Prepend "/name": the walk runs leaf -> superblock root. */
		memmove(buf + nl + 1, buf, len);
		buf[0] = '/';
		memcpy(buf + 1, d->d_name.name, nl);
		len += nl + 1;
		d = READ_ONCE(d->d_parent);
	}
	if (!len) {
		buf[0] = '/';
		len = 1;
	}
	return len;
}

#define MH_ROOT_BUF 256

static bool mh_line_hidden(enum mh_kind kind, const char *buf, size_t len,
			   struct vfsmount *mnt)
{
	struct mh_line l;
	char rootbuf[MH_ROOT_BUF];
	bool ok;

	switch (kind) {
	case MH_K_MOUNTINFO:
		ok = mh_parse_mountinfo(buf, len, &l);
		break;
	case MH_K_VFSSTAT:
		ok = mh_parse_vfsstat(buf, len, &l);
		break;
	default:
		ok = mh_parse_vfsmnt(buf, len, &l);
		break;
	}
	if (!ok)
		return false;

	/*
	 * /proc/mounts and /proc/mountstats have no root column, while
	 * mountinfo does and one of the signatures below keys on it.  Without it
	 * the same mount would be hidden from one file and listed by the other,
	 * which is exactly the cross-view difference a detector looks for.  Both
	 * show functions are handed the mount, so the string mountinfo prints can
	 * be rebuilt here.
	 */
	if (kind == MH_K_VFSMNT || kind == MH_K_VFSSTAT) {
		size_t rl = mh_mount_root(mnt, rootbuf, sizeof(rootbuf));

		if (rl) {
			l.root = rootbuf;
			l.root_len = rl;
		}
	}

	if (mh_ws_path_n(l.point, strlen(l.point)))
		return true;
	if (atomic_read(&g_anchor_count)) {
		struct mh_anchor *a;
		bool hide;

		rcu_read_lock();
		a = mh_name_match(l.point, strlen(l.point));
		hide = a && mh_record_hides(a, &l) && !mh_anchor_exempt(a->id);
		rcu_read_unlock();
		if (hide)
			return true;
	}
	if (l.source && (mh_source_token(l.source, l.source_len) ||
			 mh_staging_path(l.source, l.source_len)))
		return true;
	/*
	 * Module file binds show up with the root-manager staging tree as both
	 * the mountinfo root and the mountstats device, so check the root for
	 * the workspace pattern too: a moved skeleton can carry a root below a
	 * private workspace.
	 */
	if (l.root && (mh_staging_path(l.root, l.root_len) ||
		       mh_ws_path_n(l.root, l.root_len)))
		return true;
	return false;
}

/* "vfs_getattr+0x0" style token: one of the entry points probed here. */
static bool mh_probe_self_line(const char *s, size_t n)
{
	static const char *const syms[] = {
		"vfs_getattr", "vfs_statfs", "show_mountinfo", "show_vfsmnt",
		"show_vfsstat", "m_show", "show_kprobe_addr", "s_show",
		"kernfs_fop_readdir",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(syms); i++) {
		size_t sl = strlen(syms[i]), j;

		for (j = 0; j + sl + 4 <= n; j++) {
			if (memcmp(s + j, syms[i], sl))
				continue;
			if (s[j + sl] != '+' || s[j + sl + 1] != '0' ||
			    s[j + sl + 2] != 'x' || s[j + sl + 3] != '0')
				continue;
			/* Offset 0 is printed as "%x" -> exactly "+0x0". */
			if (j + sl + 4 < n && mh_is_hex(s[j + sl + 4]))
				continue;
			return true;
		}
	}
	return false;
}

/*
 * Hide show_kprobe_addr() lines belonging to this module.  The whole bucket is
 * emitted by a single call, so matching lines are compacted out one by one
 * instead of truncating everything the call appended.
 */
static void mh_filter_lines(struct seq_file *m, size_t start, size_t end)
{
	size_t r = start, w = start;

	while (r < end) {
		size_t e = r;
		bool keep;

		while (e < end && m->buf[e] != '\n')
			e++;
		if (e < end)
			e++; /* include the newline */
		keep = !mh_probe_self_line(m->buf + r, e - r);
		if (keep) {
			if (w != r)
				memmove(m->buf + w, m->buf + r, e - r);
			w += e - r;
		}
		r = e;
	}
	m->count = w;
}

/* ------------------------------------------------------------------ */
/* kretprobe handlers: seq_file views                                  */
/* ------------------------------------------------------------------ */

/* Substring test for a fixed token, used by the kallsyms filter. */
static bool mh_has_token(const char *s, size_t n, const char *tok)
{
	size_t tl = strlen(tok), i;

	if (n < tl)
		return false;
	for (i = 0; i + tl <= n; i++)
		if (!memcmp(s + i, tok, tl))
			return true;
	return false;
}

static int mh_seq_entry(struct kretprobe_instance *ri, struct pt_regs *regs,
			enum mh_kind kind)
{
	struct mh_seq_inst *d = (struct mh_seq_inst *)ri->data;
	struct seq_file *m = (struct seq_file *)MH_PARM1(regs);

	d->mnt = NULL;

	/*
	 * /proc/kallsyms lists this module's own symbol names.  That is not a
	 * mount decision, so it is hidden from every reader in every mode -
	 * including root, whose fsuid the APPS policy would otherwise let
	 * through.
	 */
	if (kind == MH_K_KALLSYMS) {
		if (!m || !m->buf)
			return 1;
		d->m = m;
		d->start = m->count;
		return 0;
	}

	if (!mh_hide_for_current())
		return 1;

	if (kind == MH_K_MODULES) {
		/* m_show() is handed &module->list, not the module itself. */
		if ((void *)MH_PARM2(regs) != (void *)&THIS_MODULE->list)
			return 1;
	}
	/* MOUNTINFO/VFSMNT stay armed even with no records: the private
	 * workspace is recognised by name and has to be hidden regardless. */

	if (!m || !m->buf)
		return 1;

	d->m = m;
	/* show_vfsmnt()/show_vfsstat(): second argument is the mount. */
	if (kind == MH_K_VFSMNT || kind == MH_K_VFSSTAT)
		d->mnt = (struct vfsmount *)MH_PARM2(regs);
	d->start = m->count;
	return 0;
}

static int mh_seq_ret(struct kretprobe_instance *ri, struct pt_regs *regs,
		      enum mh_kind kind)
{
	struct mh_seq_inst *d = (struct mh_seq_inst *)ri->data;
	struct seq_file *m = d->m;
	size_t start, end;

	(void)regs;

	if (!m || !m->buf)
		return 0;

	start = d->start;
	end = m->count;
	/* Overflow sets count to size+1; leave that error path alone. */
	if (end <= start || end > m->size)
		return 0;

	switch (kind) {
	case MH_K_MODULES:
		/* Entry handler already proved this line is ours. */
		m->count = start;
		break;
	case MH_K_MOUNTINFO:
	case MH_K_VFSMNT:
	case MH_K_VFSSTAT:
		if (mh_line_hidden(kind, m->buf + start, end - start, d->mnt))
			m->count = start;
		break;
	case MH_K_KPROBES:
		mh_filter_lines(m, start, end);
		break;
	case MH_K_KALLSYMS:
		if (mh_has_token(m->buf + start, end - start, "[magic_hide]"))
			m->count = start;
		break;
	default:
		break;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* kretprobe handlers: /sys/module listing                             */
/* ------------------------------------------------------------------ */

/*
 * /sys/module is a kernfs directory, so the entry name is emitted through
 * dir_context->actor, not a seq_file buffer.  Swap the actor for the duration
 * of one readdir and drop the one name, forwarding everything else.
 */
struct mh_dir_inst {
	struct dir_context *ctx;
	filldir_t orig;
	u32 slot;
};

#define MH_DIR_SLOTS 4

static struct {
	struct dir_context *ctx;
	filldir_t orig;
	bool used;
} g_dir_slots[MH_DIR_SLOTS];
/*
 * Every /sys/module listing uses the same VFS actor (filldir64), so the last
 * one seen also serves as the fallback if all slots are busy.
 */
static filldir_t g_dir_orig;
static DEFINE_SPINLOCK(g_dir_lock);

/* filldir_t returns int up to 5.15 and bool from 6.1 on. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define MH_FILLDIR_RET bool
#else
#define MH_FILLDIR_RET int
#endif

static MH_FILLDIR_RET mh_dir_actor(struct dir_context *ctx, const char *name,
				   int namlen, loff_t off, u64 ino,
				   unsigned int d_type)
{
	static const char self[] = "magic_hide";
	filldir_t orig = NULL;
	unsigned long flags;
	unsigned int i;

	/* Return 0 ("emitted") without emitting: the name never reaches user. */
	if (namlen == (int)sizeof(self) - 1 &&
	    !memcmp(name, self, sizeof(self) - 1))
		return 0;

	spin_lock_irqsave(&g_dir_lock, flags);
	for (i = 0; i < MH_DIR_SLOTS; i++) {
		if (g_dir_slots[i].used && g_dir_slots[i].ctx == ctx) {
			orig = g_dir_slots[i].orig;
			break;
		}
	}
	spin_unlock_irqrestore(&g_dir_lock, flags);
	if (!orig)
		orig = READ_ONCE(g_dir_orig);

	/* No actor at all: keep iterating rather than aborting the listing. */
	return orig ? orig(ctx, name, namlen, off, ino, d_type) : 0;
}

static int mh_dir_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mh_dir_inst *d = (struct mh_dir_inst *)ri->data;
	struct file *file = (struct file *)MH_PARM1(regs);
	struct dir_context *ctx = (struct dir_context *)MH_PARM2(regs);
	struct dentry *dir;
	unsigned long flags;
	unsigned int i;

	d->ctx = NULL;
	if (!file || !ctx || !ctx->actor || !file->f_path.mnt)
		return 1;
	dir = file->f_path.dentry;
	if (!dir || dir->d_name.len != 6 ||
	    memcmp(dir->d_name.name, "module", 6))
		return 1;
	/* Top-level "module" of the sysfs mount: /sys/module. */
	if (dir->d_parent != file->f_path.mnt->mnt_root &&
	    (dir->d_parent->d_name.len != 3 ||
	     memcmp(dir->d_parent->d_name.name, "sys", 3)))
		return 1;

	spin_lock_irqsave(&g_dir_lock, flags);
	for (i = 0; i < MH_DIR_SLOTS; i++)
		if (!g_dir_slots[i].used)
			break;
	if (i == MH_DIR_SLOTS) {
		spin_unlock_irqrestore(&g_dir_lock, flags);
		return 1;
	}
	g_dir_slots[i].used = true;
	g_dir_slots[i].ctx = ctx;
	g_dir_slots[i].orig = ctx->actor;
	spin_unlock_irqrestore(&g_dir_lock, flags);

	WRITE_ONCE(g_dir_orig, ctx->actor);
	d->ctx = ctx;
	d->orig = ctx->actor;
	d->slot = i;
	WRITE_ONCE(ctx->actor, mh_dir_actor);
	return 0;
}

static int mh_dir_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mh_dir_inst *d = (struct mh_dir_inst *)ri->data;
	unsigned long flags;

	(void)regs;
	if (!d->ctx)
		return 0;
	if (READ_ONCE(d->ctx->actor) == mh_dir_actor)
		WRITE_ONCE(d->ctx->actor, d->orig);

	spin_lock_irqsave(&g_dir_lock, flags);
	if (d->slot < MH_DIR_SLOTS) {
		g_dir_slots[d->slot].used = false;
		g_dir_slots[d->slot].ctx = NULL;
		g_dir_slots[d->slot].orig = NULL;
	}
	spin_unlock_irqrestore(&g_dir_lock, flags);
	return 0;
}

/* ------------------------------------------------------------------ */
/* kretprobe handlers: security.selinux spoofing                       */
/* ------------------------------------------------------------------ */

/*
 * A file magic_mount serves from its workspace carries the label of that
 * filesystem (tmpfs), not the label the covered path had.  That is both a
 * fingerprint (`ls -Z`, `stat -c %C`, getfilecon) and a possible policy
 * mismatch, so report the context userspace sampled before the mount existed.
 *
 * The anchor is found by walking up from the dentry: a bind mount does not
 * start a new dentry tree, so the mount root is a plain ancestor.  Only paths
 * on a registered superblock take that walk.
 */
static struct mh_anchor *mh_dentry_anchor(struct dentry *d)
{
	int depth = 32;

	while (d && depth--) {
		struct mh_anchor *a = mh_hot_lookup_dentry(d);

		if (a)
			return a;
		if (d == d->d_parent)
			break;
		d = READ_ONCE(d->d_parent);
	}
	return NULL;
}

static int mh_xattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mh_xattr_inst *d = (struct mh_xattr_inst *)ri->data;
	struct dentry *dentry = MH_XATTR_DENTRY(regs);
	const char *name = MH_XATTR_NAME(regs);

	if (!READ_ONCE(g_nsid) || !dentry || !name)
		return 1;
	if (strcmp(name, "security.selinux"))
		return 1;
	if (!mh_sb_known(dentry->d_sb))
		return 1;

	d->value = MH_XATTR_VALUE(regs);
	d->size = MH_XATTR_SIZE(regs);
	d->dentry = dentry;
	return 0;
}

static int mh_xattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mh_xattr_inst *d = (struct mh_xattr_inst *)ri->data;
	struct mh_anchor *a;
	const char *sid;
	size_t len;

	if (regs_return_value(regs) < 0)
		return 0;

	rcu_read_lock();
	a = mh_dentry_anchor(d->dentry);
	if (!a || a->sid >= READ_ONCE(g_nsid)) {
		rcu_read_unlock();
		return 0;
	}
	sid = READ_ONCE(g_sid[a->sid]);
	len = sid ? strlen(sid) : 0;
	if (!len) {
		rcu_read_unlock();
		return 0;
	}
	/* size == 0 asks only for the length every getxattr() caller starts with */
	if (!d->value || !d->size) {
		MH_SET_RET(regs, len);
	} else if (len <= d->size) {
		memcpy(d->value, sid, len);
		MH_SET_RET(regs, len);
	} else {
		MH_SET_RET(regs, -ERANGE);
	}
	rcu_read_unlock();
	return 0;
}

/* ------------------------------------------------------------------ */
/* kretprobe handlers: hot vfs_statfs / vfs_getattr                    */
/* ------------------------------------------------------------------ */

static int mh_hot_entry(struct kretprobe_instance *ri, struct pt_regs *regs,
			enum mh_kind kind)
{
	struct mh_hot_inst *d = (struct mh_hot_inst *)ri->data;
	const struct path *path = (const struct path *)MH_PARM1(regs);
	void *out = (void *)MH_PARM2(regs);
	struct mh_anchor *a;
	u32 need = kind == MH_K_STATFS ?
		(MH_REC_F_TYPE | MH_REC_F_MFLAGS | MH_REC_F_STAT) :
		(MH_REC_F_DEV | MH_REC_F_INO | MH_REC_F_DSIZE);

	/*
	 * Fast path: nothing published.  Returning 1 skips the return trampoline
	 * entirely.
	 */
	if (kind == MH_K_STATFS) {
		if (!atomic_read(&g_hot_type) && !atomic_read(&g_hot_mflags) &&
		    !atomic_read(&g_hot_stat))
			return 1;
	} else if (!atomic_read(&g_hot_dev)) {
		return 1;
	}
	if (!path || !path->mnt || !out)
		return 1;

	rcu_read_lock();
	a = mh_hot_lookup(path->mnt);
	if (!a || !(a->flags & need)) {
		rcu_read_unlock();
		return 1;
	}

	/*
	 * The policy check sits after the anchor lookup on purpose.  Every
	 * stat()/statfs() in the system reaches this handler, while only the
	 * ones that resolved an anchor need the caller's uid decision; the
	 * lookup itself is a couple of hash probes with no policy work.
	 */
	if (!mh_hide_for_current()) {
		rcu_read_unlock();
		return 1;
	}

	{
		u32 flags = a->flags & need;

		mh_hit_record(a->id);

		/* This caller asked to keep the native view of this one mount. */
		if (mh_anchor_exempt(a->id)) {
			rcu_read_unlock();
			return 1;
		}

		/*
		 * st_dev describes a filesystem and is valid for every path in
		 * the mount.  st_ino/size/blocks/nlink describe one inode, so
		 * they may only be applied to the mount root itself: a native
		 * entry inside a skeleton shares mnt_root with the replaced
		 * directory and would otherwise inherit its inode.
		 */
		if (kind != MH_K_STATFS && path->dentry != path->mnt->mnt_root)
			flags &= ~(MH_REC_F_INO | MH_REC_F_DSIZE);
		d->out = out;
		d->flags = flags;
		d->dev = a->dev;
		d->f_type = a->f_type;
		d->m_flags = a->m_flags;
		d->st = a->st;
		d->ks = a->ks;
	}
	rcu_read_unlock();
	return 0;
}

static int mh_hot_ret(struct kretprobe_instance *ri, struct pt_regs *regs,
		      enum mh_kind kind)
{
	struct mh_hot_inst *d = (struct mh_hot_inst *)ri->data;

	if (regs_return_value(regs))
		return 0;

	if (kind == MH_K_STATFS) {
		struct kstatfs *buf = (struct kstatfs *)d->out;

		if (d->flags & MH_REC_F_TYPE)
			buf->f_type = (long)d->f_type;
		if (d->flags & MH_REC_F_MFLAGS)
			buf->f_flags = (long)d->m_flags;
		/*
		 * Full block accounting: without these a skeleton tmpfs still
		 * reports its 64 MB size while the stock partition it hides
		 * reports gigabytes, which is an easy statfs() fingerprint.
		 */
		if (d->flags & MH_REC_F_STAT) {
			buf->f_bsize = (long)d->st.f_bsize;
			buf->f_blocks = (size_t)d->st.f_blocks;
			buf->f_bfree = (size_t)d->st.f_bfree;
			buf->f_bavail = (size_t)d->st.f_bavail;
			buf->f_files = (size_t)d->st.f_files;
			buf->f_ffree = (size_t)d->st.f_ffree;
			buf->f_namelen = (long)d->st.f_namelen;
			buf->f_frsize = (long)d->st.f_frsize;
			buf->f_fsid.val[0] = (int)(d->st.f_fsid & 0xffffffffu);
			buf->f_fsid.val[1] =
				(int)((d->st.f_fsid >> 32) & 0xffffffffu);
		}
	} else {
		struct kstat *ks = (struct kstat *)d->out;

		if (d->flags & MH_REC_F_DEV)
			ks->dev = d->dev;
		/*
		 * f2fs stores the inode number as the inode block address, so a
		 * bind-mounted module file reports a value from a completely
		 * different range than its ext4/EROFS siblings.  Same for a
		 * skeleton directory's size/blocks, which a stock directory
		 * reports as one 4 KiB block.
		 */
		if (d->flags & MH_REC_F_INO)
			ks->ino = d->ks.ino;
		if (d->flags & MH_REC_F_DSIZE) {
			ks->size = d->ks.size;
			ks->blocks = d->ks.blocks;
			ks->nlink = d->ks.nlink;
		}
	}
	return 0;
}

#define MH_SEQ_FNS(tag, kind)                                            \
	static int tag##_entry(struct kretprobe_instance *ri,            \
			       struct pt_regs *regs)                     \
	{                                                                \
		return mh_seq_entry(ri, regs, kind);                     \
	}                                                                \
	static int tag##_ret(struct kretprobe_instance *ri,              \
			     struct pt_regs *regs)                       \
	{                                                                \
		return mh_seq_ret(ri, regs, kind);                       \
	}

#define MH_HOT_FNS(tag, kind)                                            \
	static int tag##_entry(struct kretprobe_instance *ri,            \
			       struct pt_regs *regs)                     \
	{                                                                \
		return mh_hot_entry(ri, regs, kind);                     \
	}                                                                \
	static int tag##_ret(struct kretprobe_instance *ri,              \
			     struct pt_regs *regs)                       \
	{                                                                \
		return mh_hot_ret(ri, regs, kind);                       \
	}

MH_SEQ_FNS(mh_mountinfo, MH_K_MOUNTINFO)
MH_SEQ_FNS(mh_vfsmnt, MH_K_VFSMNT)
MH_SEQ_FNS(mh_vfsstat, MH_K_VFSSTAT)
MH_SEQ_FNS(mh_modules, MH_K_MODULES)
MH_SEQ_FNS(mh_kprobes, MH_K_KPROBES)
MH_SEQ_FNS(mh_kallsyms, MH_K_KALLSYMS)
MH_HOT_FNS(mh_statfs, MH_K_STATFS)
MH_HOT_FNS(mh_getattr, MH_K_GETATTR)

#define MH_SEQ_RP(sym, tag)                                              \
	{                                                                \
		.kp = { .symbol_name = sym },                             \
		.entry_handler = tag##_entry,                            \
		.handler = tag##_ret,                                    \
		.data_size = sizeof(struct mh_seq_inst),                 \
		.maxactive = 32,                                         \
	}

#define MH_HOT_RP(sym, tag, maxact)                                      \
	{                                                                \
		.kp = { .symbol_name = sym },                             \
		.entry_handler = tag##_entry,                            \
		.handler = tag##_ret,                                    \
		.data_size = sizeof(struct mh_hot_inst),                 \
		.maxactive = maxact,                                     \
	}

static struct kretprobe g_rp_mountinfo =
	MH_SEQ_RP("show_mountinfo", mh_mountinfo);
static struct kretprobe g_rp_vfsmnt = MH_SEQ_RP("show_vfsmnt", mh_vfsmnt);
static struct kretprobe g_rp_vfsstat = MH_SEQ_RP("show_vfsstat", mh_vfsstat);
static struct kretprobe g_rp_modules = MH_SEQ_RP("m_show", mh_modules);
static struct kretprobe g_rp_kprobes = MH_SEQ_RP("show_kprobe_addr", mh_kprobes);
static struct kretprobe g_rp_kallsyms = MH_SEQ_RP("s_show", mh_kallsyms);

/* Optional: hides /sys/module's entry for this module. */
static struct kretprobe g_rp_readdir = {
	.kp = { .symbol_name = "kernfs_fop_readdir" },
	.entry_handler = mh_dir_entry,
	.handler = mh_dir_ret,
	.data_size = sizeof(struct mh_dir_inst),
	.maxactive = 8,
};

/*
 * vfs_getattr() is on the hottest path in the system; give it a larger
 * instance pool so nested/parallel calls do not silently lose the rewrite,
 * while the entry handler keeps the miss path allocation-free.  The same
 * applies to vfs_statfs(): a package scan has many threads in it at once.
 */
static struct kretprobe g_rp_statfs =
	MH_HOT_RP("vfs_statfs", mh_statfs, 64);
static struct kretprobe g_rp_getattr =
	MH_HOT_RP("vfs_getattr", mh_getattr, 256);

static struct kretprobe g_rp_xattr = {
	.kp = { .symbol_name = "vfs_getxattr" },
	.entry_handler = mh_xattr_entry,
	.handler = mh_xattr_ret,
	.data_size = sizeof(struct mh_xattr_inst),
	.maxactive = 128,
};

static bool g_reg_mountinfo;
static bool g_reg_vfsmnt;
static bool g_reg_vfsstat;
static bool g_reg_modules;
static bool g_reg_kprobes;
static bool g_reg_kallsyms;
static bool g_reg_readdir;
static bool g_reg_statfs;
static bool g_reg_getattr;
static bool g_reg_xattr;

static void mh_hot_unregister(void)
{
	if (g_reg_xattr) {
		unregister_kretprobe(&g_rp_xattr);
		g_reg_xattr = false;
	}
	if (g_reg_statfs) {
		unregister_kretprobe(&g_rp_statfs);
		g_reg_statfs = false;
	}
	if (g_reg_getattr) {
		unregister_kretprobe(&g_rp_getattr);
		g_reg_getattr = false;
	}
}

static void mh_hot_register(void)
{
	int ret;

	if (READ_ONCE(g_mode) == MH_MODE_OFF)
		return;

	if (!g_reg_statfs &&
	    (atomic_read(&g_hot_type) || atomic_read(&g_hot_mflags) ||
	     atomic_read(&g_hot_stat))) {
		ret = register_kretprobe(&g_rp_statfs);
		if (ret)
			pr_debug("cannot probe vfs_statfs: %d\n", ret);
		else
			g_reg_statfs = true;
	}
	if (!g_reg_getattr && atomic_read(&g_hot_dev)) {
		ret = register_kretprobe(&g_rp_getattr);
		if (ret)
			pr_debug("cannot probe vfs_getattr: %d\n", ret);
		else
			g_reg_getattr = true;
	}
	if (!g_reg_xattr && READ_ONCE(g_nsid) && atomic_read(&g_hot_count)) {
		ret = register_kretprobe(&g_rp_xattr);
		if (ret)
			pr_debug("cannot probe vfs_getxattr: %d\n", ret);
		else
			g_reg_xattr = true;
	}
}

/* ------------------------------------------------------------------ */
/* payload processing (key type -> preparse, process context)          */
/* ------------------------------------------------------------------ */

static int mh_payload_add(struct mh_upayload *pl)
{
	u32 count = pl->hdr.count;
	u32 dsize = pl->hdr.data_size;
	u32 recbytes, i;
	int ret = 0;

	if (dsize > MH_BUF_MAX)
		return -EINVAL;
	if (count > MH_BUF_MAX / sizeof(struct mh_urec))
		return -EINVAL;
	recbytes = count * (u32)sizeof(struct mh_urec);
	if (recbytes > dsize)
		return -EINVAL;

	for (i = 0; i < count; i++) {
		const struct mh_urec *rec =
			(const struct mh_urec *)(pl->buf + i * sizeof(*rec));
		u64 off = rec->path_off;
		u32 len = rec->path_len;
		const char *name;

		if (!len || len > MH_PATH_MAX || off < recbytes ||
		    off + len > dsize) {
			if (!ret)
				ret = -EINVAL;
			continue;
		}
		name = (const char *)pl->buf + off;
		if (memchr(name, 0, len)) {
			if (!ret)
				ret = -EINVAL;
			continue;
		}
		if (mh_records_add(name, len, rec->flags, rec->dev,
				   rec->f_type, rec->m_flags,
				   (rec->flags & MH_REC_F_STAT) ? &rec->st :
								  NULL,
				   (rec->flags & (MH_REC_F_INO | MH_REC_F_DSIZE)) ?
					   &rec->ks : NULL,
				   rec->sid) < 0 && !ret)
			ret = -ENOMEM;
	}
	mh_hot_register();
	return ret;
}

static int mh_process_payload(unsigned long user_addr)
{
	struct mh_upayload *pl;
	struct page *page;
	unsigned long off = offset_in_page(user_addr);
	int ret = 0;

	if (off + sizeof(struct mh_upayload) > PAGE_SIZE)
		return -EFAULT;
	if (get_user_pages_fast(user_addr, 1, FOLL_WRITE, &page) != 1)
		return -EFAULT;

	pl = (struct mh_upayload *)((char *)kmap(page) + off);
	if (pl->hdr.magic != MH_PAYLOAD_MAGIC ||
	    pl->hdr.version != MH_PAYLOAD_VERSION) {
		ret = -EINVAL;
		goto out;
	}

	pl->hdr.status = 0;
	switch (pl->hdr.cmd) {
	case MH_CMD_RESET:
		mh_hot_unregister();
		mh_records_reset();
		break;
	case MH_CMD_OFF:
		mh_hot_unregister();
		mh_records_reset();
		WRITE_ONCE(g_mode, MH_MODE_OFF);
		break;
	case MH_CMD_MODE:
		if (pl->hdr.mode > MH_MODE_OFF) {
			ret = -EINVAL;
			break;
		}
		WRITE_ONCE(g_mode, (enum mh_mode)pl->hdr.mode);
		if (pl->hdr.mode == MH_MODE_OFF)
			mh_hot_unregister();
		else
			mh_hot_register();
		break;
	case MH_CMD_ADD:
		ret = mh_payload_add(pl);
		break;
	case MH_CMD_REFRESH:
		ret = mh_records_refresh();
		break;
	case MH_CMD_POLICY:
		if (pl->hdr.count > MH_POLICY_MAX ||
		    pl->hdr.data_size < pl->hdr.count * (u32)sizeof(struct mh_upolicy) ||
		    pl->hdr.data_size > MH_BUF_MAX) {
			ret = -EINVAL;
			break;
		}
		mutex_lock(&g_mutex);
		ret = mh_set_policy((const struct mh_upolicy *)pl->buf,
				    pl->hdr.count);
		mutex_unlock(&g_mutex);
		break;
	case MH_CMD_CONFIG:
		if (pl->hdr.count < 1 || pl->hdr.count > 4 ||
		    pl->hdr.data_size < pl->hdr.count * (u32)sizeof(mh_u64)) {
			ret = -EINVAL;
			break;
		}
		ret = mh_set_addrs((const mh_u64 *)pl->buf, pl->hdr.count);
		break;
	case MH_CMD_EVENTS:
		pl->hdr.count = mh_events_dump(pl, pl->hdr.mode != 0);
		pl->hdr.data_size = pl->hdr.count * (u32)sizeof(struct mh_uevent);
		break;
	case MH_CMD_HITS:
		pl->hdr.count = mh_hits_dump(pl, pl->hdr.mode != 0);
		pl->hdr.data_size = pl->hdr.count * (u32)sizeof(struct mh_uhit);
		break;
	case MH_CMD_SID:
		if (pl->hdr.count > MH_SID_MAX || pl->hdr.data_size > MH_BUF_MAX) {
			ret = -EINVAL;
			break;
		}
		/* The return handler reads the pool locklessly: stop it first. */
		mh_hot_unregister();
		mutex_lock(&g_mutex);
		ret = mh_sid_set(pl->buf, pl->hdr.count, pl->hdr.data_size);
		mutex_unlock(&g_mutex);
		mh_hot_register();
		break;
	default:
		ret = -EINVAL;
		break;
	}
	pl->hdr.status = ret;

out:
	kunmap(page);
	set_page_dirty_lock(page);
	put_page(page);
	return ret;
}

#if IS_ENABLED(CONFIG_KEYS)
static int mh_key_preparse(struct key_preparsed_payload *prep)
{
	unsigned long user_addr = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (prep->datalen != sizeof(u64))
		return -EINVAL;
	memcpy(&user_addr, prep->data, sizeof(user_addr));
	if (user_addr)
		mh_process_payload(user_addr);
	/* Cancel key creation: nothing shows up in /proc/keys. */
	return -ECANCELED;
}

static int mh_key_instantiate(struct key *key,
			      struct key_preparsed_payload *prep)
{
	(void)key;
	(void)prep;
	return -EINVAL;
}

static void mh_key_free_preparse(struct key_preparsed_payload *prep)
{
	(void)prep;
}

static struct key_type mh_key_type = {
	.name = MH_KEY_TYPE,
	.preparse = mh_key_preparse,
	.instantiate = mh_key_instantiate,
	.free_preparse = mh_key_free_preparse,
};
static bool g_key_registered;
#endif /* CONFIG_KEYS */

/* ------------------------------------------------------------------ */
/* module setup                                                        */
/* ------------------------------------------------------------------ */

static int mh_seq_probe_register(struct kretprobe *rp, bool *registered,
				 const char *what)
{
	int ret = register_kretprobe(rp);

	if (ret) {
		pr_err("cannot probe %s: %d\n", what, ret);
		return ret;
	}
	*registered = true;
	return 0;
}

static int __init magic_hide_init(void)
{
#if IS_ENABLED(CONFIG_KEYS)
	int ret = register_key_type(&mh_key_type);

	/*
	 * The control channel is optional now: records only refine the output,
	 * the signature rules do not need them.  Never fail the whole module
	 * because a private key type could not be registered.
	 */
	if (ret)
		pr_err("cannot register key type: %d (continuing)\n", ret);
	else
		g_key_registered = true;
#endif

	mh_seq_probe_register(&g_rp_mountinfo, &g_reg_mountinfo,
			      "show_mountinfo");
	mh_seq_probe_register(&g_rp_vfsmnt, &g_reg_vfsmnt, "show_vfsmnt");
	mh_seq_probe_register(&g_rp_vfsstat, &g_reg_vfsstat, "show_vfsstat");
	mh_seq_probe_register(&g_rp_modules, &g_reg_modules, "m_show");
	mh_seq_probe_register(&g_rp_kprobes, &g_reg_kprobes,
			      "show_kprobe_addr");
	/*
	 * Cosmetic: drops this module's own names from /proc/kallsyms.  A
	 * kernel built without CONFIG_KALLSYMS has no s_show, and that is not
	 * a reason to refuse to load.
	 */
	if (register_kretprobe(&g_rp_kallsyms))
		pr_debug("cannot probe s_show\n");
	else
		g_reg_kallsyms = true;
	/*
	 * Same idea for /sys/module: a kernel whose kernfs readdir entry point
	 * is not named `kernfs_fop_readdir` simply keeps the sysfs directory
	 * visible.  Unconditional, like the /proc/modules and kallsyms hooks.
	 */
	if (register_kretprobe(&g_rp_readdir))
		pr_debug("cannot probe kernfs_fop_readdir\n");
	else
		g_reg_readdir = true;

	if (!g_reg_mountinfo && !g_reg_vfsmnt && !g_reg_vfsstat &&
	    !g_reg_modules && !g_reg_kprobes) {
#if IS_ENABLED(CONFIG_KEYS)
		if (g_key_registered)
			unregister_key_type(&mh_key_type);
#endif
		pr_err("no hook could be installed\n");
		return -ENOENT;
	}
	pr_info("loaded: mountinfo=%d vfsmnt=%d vfsstat=%d modules=%d kprobes=%d kallsyms=%d readdir=%d mode=%d ftrace=%d params=%d\n",
		g_reg_mountinfo, g_reg_vfsmnt, g_reg_vfsstat, g_reg_modules,
		g_reg_kprobes, g_reg_kallsyms, g_reg_readdir, (int)g_mode,
		MH_HAVE_FTRACE, mh_ft_have_params());
	return 0;
}

static void __exit magic_hide_exit(void)
{
	mh_ft_unregister();
#if IS_ENABLED(CONFIG_KEYS)
	if (g_key_registered)
		unregister_key_type(&mh_key_type);
#endif

	mh_hot_unregister();
	mh_records_reset();

	/* The probe on its own show function goes last. */
	if (g_reg_kprobes)
		unregister_kretprobe(&g_rp_kprobes);
	if (g_reg_kallsyms)
		unregister_kretprobe(&g_rp_kallsyms);
	if (g_reg_readdir)
		unregister_kretprobe(&g_rp_readdir);
	if (g_reg_modules)
		unregister_kretprobe(&g_rp_modules);
	if (g_reg_mountinfo)
		unregister_kretprobe(&g_rp_mountinfo);
	if (g_reg_vfsmnt)
		unregister_kretprobe(&g_rp_vfsmnt);
	if (g_reg_vfsstat)
		unregister_kretprobe(&g_rp_vfsstat);
}

module_init(magic_hide_init);
module_exit(magic_hide_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Native VFS view for magic_mount");
MODULE_AUTHOR("magic_mount");
