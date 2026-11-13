/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared control interface between magic_mount (userspace) and magic_hide.ko.
 *
 * The LKM registers a private key type.  Userspace hands it the address of one
 * page-aligned payload page through add_key(); the kernel's ->preparse()
 * callback pins that page, applies the command in place and writes the result
 * back into hdr.status.  No /proc or /sys control file is ever created, so
 * there is nothing to enumerate from userspace.
 */

#ifndef MAGIC_HIDE_UAPI_H
#define MAGIC_HIDE_UAPI_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8  mh_u8;
typedef u16 mh_u16;
typedef u32 mh_u32;
typedef u64 mh_u64;
typedef s32 mh_s32;
#else
#include <stdint.h>
typedef uint8_t  mh_u8;
typedef uint16_t mh_u16;
typedef uint32_t mh_u32;
typedef uint64_t mh_u64;
typedef int32_t  mh_s32;
#endif

#define MH_PAGE_SIZE        4096u
#define MH_PAYLOAD_MAGIC    0x4d485359u /* "MHSY" */
#define MH_PAYLOAD_VERSION  4u /* 4: POLICY + EVENTS (process-level) */
#define MH_PATH_MAX         512

/* Key type used by the LKM; add_key() is cancelled right after it runs. */
#define MH_KEY_TYPE "mh_sync"
#define MH_KEY_DESC "sync"

enum mh_cmd {
	MH_CMD_RESET = 0, /* drop every record and unregister hot probes   */
	MH_CMD_ADD   = 1, /* append records (mountpoints + native metadata) */
	MH_CMD_MODE  = 2, /* change the per-uid visibility policy           */
	MH_CMD_OFF   = 3, /* RESET + MH_MODE_OFF                            */
	MH_CMD_REFRESH = 4, /* re-resolve paths, keep the published identity */
	MH_CMD_POLICY = 5, /* replace the exempt uid set (process-level)     */
	MH_CMD_EVENTS = 6, /* dump observed syscall callers, then clear      */
};

enum mh_mode {
	MH_MODE_APPS = 0, /* hide/fake for every uid except 0           */
	MH_MODE_ALL  = 1, /* hide/fake for everyone (default)           */
	MH_MODE_OFF  = 2, /* expose the real state to everyone          */
};

#define MH_REC_F_TYPE   0x01u /* record carries a native f_type          */
#define MH_REC_F_DEV    0x02u /* record carries a native (kernel) st_dev */
#define MH_REC_F_MFLAGS 0x04u /* record carries the mount flag word      */
#define MH_REC_F_STAT   0x08u /* record carries the statfs counters      */
#define MH_REC_F_INO    0x10u /* record carries a plausible st_ino       */
#define MH_REC_F_DSIZE  0x20u /* record carries dir size/blocks/nlink    */

/* Inode-level fields of a covered path, sampled before it is mounted over. */
struct mh_ukstat {
	mh_u64 ino;
	mh_u64 size;
	mh_u64 blocks;
	mh_u64 nlink;
};

/*
 * The block accounting fields of statfs() on the covered partition.  They are
 * all 64 bit because the LKM only builds for 64 bit kernels (see the
 * CONFIG_ARM64 / CONFIG_X86_64 guard); f_fsid holds val[0] in the low and
 * val[1] in the high 32 bits.  Userspace samples this once per mountpoint from
 * the pre-mount snapshot, so a skeleton tmpfs cannot advertise its 64 MB size
 * while the real partition has gigabytes.
 */
struct mh_ustatfs {
	mh_u64 f_bsize;
	mh_u64 f_blocks;
	mh_u64 f_bfree;
	mh_u64 f_bavail;
	mh_u64 f_files;
	mh_u64 f_ffree;
	mh_u64 f_namelen;
	mh_u64 f_frsize;
	mh_u64 f_fsid;
};

/*
 * One observed caller of the stat family, reported by the ftrace probe on the
 * syscall wrappers.  The LKM keeps a fixed direct-mapped table keyed by uid and
 * MH_CMD_EVENTS returns it, so the module can decide which processes should be
 * exempt from hiding (see MH_CMD_POLICY).  op: 0 statx, 1 newfstatat, 2 statfs,
 * 3 fstatfs.
 */
#define MH_EV_MAX   64
#define MH_COMM_LEN 16

struct mh_uevent {
	mh_u32 uid;
	mh_u32 pid;
	mh_u32 op;
	mh_u32 count;
	mh_u8 comm[MH_COMM_LEN];
};

/*
 * One published mountpoint.  path_off/path_len point into mh_upayload.buf and
 * are relative to the start of that buffer.  dev is already in the kernel
 * dev_t encoding, i.e. (major << 20) | minor.  m_flags is the value
 * statfs().f_flags must report for the covered path (ST_RDONLY, ST_NOSUID,
 * ST_NODEV, ST_NOEXEC, ST_NOATIME, ST_NODIRATIME, ST_RELATIME, ...).
 */
struct mh_urec {
	mh_u32 path_off;
	mh_u32 path_len;
	mh_u64 dev;
	mh_u64 f_type;
	mh_u32 flags;
	mh_u32 m_flags;
	struct mh_ustatfs st; /* valid when MH_REC_F_STAT is set */
	struct mh_ukstat ks;  /* valid when MH_REC_F_INO / _DSIZE is set */
};

struct mh_uhdr {
	mh_u32 magic;
	mh_u32 version;
	mh_u32 cmd;
	mh_u32 mode;
	mh_s32 status;  /* kernel -> userspace result, 0 on success */
	mh_u32 count;
	mh_u32 data_size;
	mh_u32 reserved;
};

#define MH_BUF_MAX (MH_PAGE_SIZE - sizeof(struct mh_uhdr))

struct mh_upayload {
	struct mh_uhdr hdr;
	mh_u8 buf[MH_BUF_MAX];
};

#endif /* MAGIC_HIDE_UAPI_H */
