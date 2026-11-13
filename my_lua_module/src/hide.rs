//! Userspace half of the `magic_hide.ko` control channel.
//!
//! The LKM registers a private key type, so the only way to talk to it is
//! `add_key("mh_sync", "sync", &page_ptr, 8, -1)`: the kernel pins that page,
//! runs the command in place and cancels the key again (nothing appears in
//! `/proc/keys`).  There is deliberately no public control node.
//!
//! Two things are published:
//!
//!   * every mountpoint magic_mount creates, so the LKM can drop the matching
//!     `/proc/*/mountinfo`, `/proc/*/mounts` and `/proc/*/mountstats` lines;
//!   * the filesystem identity that mountpoint had *before* it was covered
//!     (`st_dev`, `statfs().f_type` and `statfs().f_flags`), so
//!     `stat()`/`statfs()`/`statvfs()` on the replaced path still answer with
//!     the real partition instead of tmpfs.
//!
//! The identity is taken from a `/proc/self/mountinfo` snapshot that is read
//! once, before the first mount exists: `dev` comes from the mount's
//! `major:minor`, `f_type`/`f_flags` from one `statfs()` per distinct
//! mountpoint.  Per-file lookups after that are pure memory, which keeps a
//! module with thousands of files from issuing two syscalls per file.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

const MH_PAGE_SIZE: usize = 4096;
const MH_PAYLOAD_MAGIC: u32 = 0x4d48_5359; // "MHSY"
const MH_PAYLOAD_VERSION: u32 = 6; // 6: HITS (per-uid hit buckets)
const MH_PATH_MAX: usize = 512;
const MH_BUF_MAX: usize = MH_PAGE_SIZE - std::mem::size_of::<Uhdr>();

const MH_CMD_RESET: u32 = 0;
const MH_CMD_ADD: u32 = 1;
const MH_CMD_MODE: u32 = 2;
const MH_CMD_REFRESH: u32 = 4;
const MH_CMD_POLICY: u32 = 5;
const MH_CMD_EVENTS: u32 = 6;
const MH_CMD_CONFIG: u32 = 7;
const MH_CMD_HITS: u32 = 8;

const MH_MODE_ALL: u32 = 1;

const MH_REC_F_TYPE: u32 = 0x01;
const MH_REC_F_DEV: u32 = 0x02;
const MH_REC_F_MFLAGS: u32 = 0x04;
const MH_REC_F_STAT: u32 = 0x08;
const MH_REC_F_INO: u32 = 0x10;
const MH_REC_F_DSIZE: u32 = 0x20;

/* statfs().f_flags bits (asm-generic/statfs.h).  The per-mount ones are
 * numerically identical to the old MS_* mount bits, which is why the same
 * word can be handed to mount(2) below. */
pub const ST_RDONLY: u32 = 0x0001;
pub const ST_NOSUID: u32 = 0x0002;
pub const ST_NODEV: u32 = 0x0004;
pub const ST_NOEXEC: u32 = 0x0008;
pub const ST_SYNCHRONOUS: u32 = 0x0010;
pub const ST_MANDLOCK: u32 = 0x0040;
pub const ST_DIRSYNC: u32 = 0x0080;
pub const ST_NOATIME: u32 = 0x0400;
pub const ST_NODIRATIME: u32 = 0x0800;
pub const ST_RELATIME: u32 = 0x1000;

/// The `f_flags` bits that also exist as per-mount flags.  `ST_VALID`,
/// `ST_APPEND`, `ST_IMMUTABLE` and `ST_NOSYMFOLLOW` are superblock/inode
/// properties and must never be fed back into `mount(2)`.
pub const MIRROR_FLAGS_MASK: u32 = ST_RDONLY
    | ST_NOSUID
    | ST_NODEV
    | ST_NOEXEC
    | ST_SYNCHRONOUS
    | ST_MANDLOCK
    | ST_DIRSYNC
    | ST_NOATIME
    | ST_NODIRATIME
    | ST_RELATIME;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Urec {
    path_off: u32,
    path_len: u32,
    dev: u64,
    f_type: u64,
    flags: u32,
    m_flags: u32,
    st: Ustatfs,
    ks: Ukstat,
}

/// Wire layout of `struct mh_ukstat`: the inode-level fields of the covered
/// path.  `ino` is always present; `size/blocks/nlink` are only for the
/// directory roots a skeleton replaces.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Ukstat {
    ino: u64,
    size: u64,
    blocks: u64,
    nlink: u64,
}

/// Wire layout of `struct mh_ustatfs`: the block accounting part of `statfs()`
/// on the covered partition, sampled once per mountpoint before any mount
/// exists.  `f_fsid` keeps `val[0]` in the low and `val[1]` in the high word.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Ustatfs {
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_namelen: u64,
    f_frsize: u64,
    f_fsid: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Uhdr {
    magic: u32,
    version: u32,
    cmd: u32,
    mode: u32,
    status: i32,
    count: u32,
    data_size: u32,
    reserved: u32,
}

/// Identity sampled from an existing path before magic_mount covers it.
#[derive(Clone, Copy, Default)]
struct Native {
    dev: u64,
    f_type: u64,
    flags: u32,
    m_flags: u32,
    st: Ustatfs,
    ks: Ukstat,
}

/// One pre-existing mount: where it is and what it reports.
struct MountEntry {
    point: Vec<u8>,
    dev: u64,
    f_type: Option<u64>,
    m_flags: u32,
    st: Option<Ustatfs>,
}

/// Everything magic_mount touched, published to the LKM in one go.
pub struct MountTable {
    records: Mutex<HashMap<PathBuf, Native>>,
    mounts: Option<Vec<MountEntry>>,
    /// Top-level component -> its real directory.  ROMs symlink partitions
    /// (`/product -> /my_product`), while mountinfo only knows the resolved
    /// mountpoint, so a raw-byte lookup would fall back to `/` and report the
    /// root filesystem's dev instead of the partition's.
    roots: Mutex<HashMap<PathBuf, PathBuf>>,
}

impl MountTable {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            mounts: Some(snapshot_mounts()),
            roots: Mutex::new(HashMap::new()),
        }
    }

    /// Remember what `path` is supposed to look like after the mount is in
    /// place.  Uses the pre-mount snapshot and one `stat()` of the path, so
    /// the identity is read before anything covers it.
    pub fn record<P: AsRef<Path>>(&self, path: P) {
        let path = path.as_ref();
        let lookup = self.resolve(path);
        let stock = stock_stat(path);

        let native = self
            .mounts
            .as_deref()
            .and_then(|mounts| covering_mount(mounts, &lookup))
            .map(|m| {
                let mut flags = MH_REC_F_DEV | MH_REC_F_MFLAGS;
                let f_type = match m.f_type {
                    Some(t) => {
                        flags |= MH_REC_F_TYPE;
                        t
                    }
                    None => 0,
                };
                if m.st.is_some() {
                    flags |= MH_REC_F_STAT;
                }
                Native {
                    dev: m.dev,
                    f_type,
                    flags,
                    m_flags: m.m_flags,
                    st: m.st.unwrap_or_default(),
                    ks: Ukstat::default(),
                }
            })
            .or_else(|| sample(path));

        let Some(mut native) = native else { return };

        // A stock path yields its exact inode; a module-added path gets a
        // small stable value so it does not stand out as an f2fs block address.
        match stock {
            Some(stock) => {
                native.ks.ino = stock.ino;
                if stock.is_dir {
                    native.ks.size = stock.size;
                    native.ks.blocks = stock.blocks;
                    native.ks.nlink = stock.nlink;
                    native.flags |= MH_REC_F_DSIZE;
                }
                native.flags |= MH_REC_F_INO;
            }
            None => {
                native.ks.ino = synth_ino(path);
                native.flags |= MH_REC_F_INO;
            }
        }

        self.lock().insert(path.to_path_buf(), native);
    }

    /// Resolve the first path component so `/product/...` maps to the real
    /// `/my_product/...` mount when the ROM uses a symlink.  The result is
    /// cached: there are only a handful of partitions, so this costs a few
    /// `readlink` calls for the whole mount run.
    fn resolve(&self, path: &Path) -> PathBuf {
        // `iter()` yields "/" first for an absolute path; skip the root and
        // take the first real component (`product` in `/product/...`).
        let first = path
            .components()
            .find(|c| matches!(c, std::path::Component::Normal(_)));
        let Some(first) = first else {
            return path.to_path_buf();
        };
        let root = Path::new("/").join(first.as_os_str());
        let Ok(rest) = path.strip_prefix(&root) else {
            return path.to_path_buf();
        };
        if rest.as_os_str().is_empty() {
            return path.to_path_buf();
        }

        let cached = self.root_cache().get(&root).cloned();
        let real = match cached {
            Some(real) => real,
            None => {
                let real = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
                self.root_cache().insert(root.clone(), real.clone());
                real
            }
        };
        if real == root {
            path.to_path_buf()
        } else {
            real.join(rest)
        }
    }

    fn root_cache(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, PathBuf>> {
        self.roots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Per-mount flags the covered filesystem reports for `path`.  Call after
    /// `record()`, which stores the pre-mount identity.  Returns `None` when no
    /// record exists (for example when mountinfo could not be read).
    pub fn native_flags<P: AsRef<Path>>(&self, path: P) -> Option<u32> {
        self.lock().get(path.as_ref()).map(|n| n.m_flags)
    }

    /// Number of mountpoints handed to the LKM; reported next to the stage
    /// timings so a change in tree shape shows up alongside a change in time.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn publish(&self) {
        let records = self.lock();
        if records.is_empty() {
            return;
        }
        let entries = records
            .iter()
            .map(|(path, native)| (path.clone(), *native))
            .collect::<Vec<_>>();
        drop(records);

        let Some(mut payload) = Payload::new() else {
            return;
        };

        if !payload.send(MH_CMD_RESET, 0, 0) {
            return;
        }

        let mut i = 0;
        let mut published: Vec<PathBuf> = Vec::with_capacity(entries.len());
        while i < entries.len() {
            let mut n = 0usize;
            let mut strings = 0usize;

            while i + n < entries.len() {
                let len = entries[i + n].0.as_os_str().as_bytes().len();
                if len == 0 || len >= MH_PATH_MAX {
                    break;
                }
                let need = (n + 1) * std::mem::size_of::<Urec>() + strings + len + 1;
                if need > MH_BUF_MAX {
                    break;
                }
                strings += len + 1;
                n += 1;
            }
            if n == 0 {
                i += 1; // path too long for a record: skip it
                continue;
            }

            let recsize = n * std::mem::size_of::<Urec>();
            let mut off = recsize;
            {
                let buf = payload.buf_mut();
                for k in 0..n {
                    let (path, native) = &entries[i + k];
                    let bytes = path.as_os_str().as_bytes();
                    let rec = Urec {
                        path_off: off as u32,
                        path_len: bytes.len() as u32,
                        dev: native.dev,
                        f_type: native.f_type,
                        flags: native.flags,
                        m_flags: native.m_flags,
                        st: native.st,
                        ks: native.ks,
                    };
                    let at = k * std::mem::size_of::<Urec>();
                    buf[at..at + std::mem::size_of::<Urec>()].copy_from_slice(&to_bytes(&rec));
                    buf[off..off + bytes.len()].copy_from_slice(bytes);
                    buf[off + bytes.len()] = 0;
                    off += bytes.len() + 1;
                }
            }
            if !payload.send(MH_CMD_ADD, n as u32, off as u32) {
                break;
            }
            published.extend(entries[i..i + n].iter().map(|(p, _)| p.clone()));
            i += n;
        }

        // Hide from every uid, including the root zygote_next services.
        payload.send(MH_CMD_MODE, 0, 0);
        // Start counting which uids actually reach a covered mount.  The kernel
        // only increments after a hot lookup already matched, and the table is
        // drained once by report(); until then it costs a 32 slot scan.
        payload.send_mode(MH_CMD_HITS, 1, 0, 0);
        // The kernel names a hit bucket by the index of the record it matched,
        // so keep the same order to resolve an id back to a path later.
        *RECORDS.lock().unwrap_or_else(|e| e.into_inner()) = published;
        log::info!("published {} mountpoints to magic_hide", entries.len());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, Native>> {
        self.records.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Ask the LKM to rebind the published identity to the mounts that exist now.
///
/// The kernel keys its lookup on the covered mount's root dentry, so a mount
/// created after `publish()` (a root manager remounting a partition, a module
/// installed later, a bind redone) carries a different dentry and the old
/// records stop matching.  Refreshing re-resolves the stored paths and keeps
/// the identity that was sampled before the first mount, so calling this at
/// every later lifecycle stage is safe and idempotent.
pub fn refresh() -> bool {
    match Payload::new() {
        Some(mut payload) => payload.send(MH_CMD_REFRESH, 0, 0),
        None => false,
    }
}

const MH_EV_MAX: usize = 64;
const MH_EXEMPT_MAX: usize = 64;
const MH_COMM_LEN: usize = 16;

/// Wire layout of `struct mh_uevent`: one caller of the stat family, as seen by
/// the LKM's ftrace probe on the syscall wrappers.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Uevent {
    uid: u32,
    pid: u32,
    op: u32,
    count: u32,
    comm: [u8; MH_COMM_LEN],
}

/// One process that called stat/statfs, coalesced per uid by the kernel.
#[derive(Clone, Copy, Default)]
pub struct Observer {
    pub uid: u32,
    pub pid: u32,
    pub op: u32,
    pub count: u32,
    comm: [u8; MH_COMM_LEN],
}

impl Observer {
    /// `comm` is a fixed 16-byte field, not necessarily NUL terminated.
    pub fn comm(&self) -> String {
        let end = self.comm.iter().position(|c| *c == 0).unwrap_or(MH_COMM_LEN);
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }

    pub fn op_name(&self) -> &'static str {
        match self.op {
            0 => "statx",
            1 => "newfstatat",
            2 => "statfs",
            3 => "fstatfs",
            _ => "?",
        }
    }
}

/// Processes that must keep seeing the real mount table.  An empty slice clears
/// the set, which restores the default of hiding from everyone.
pub fn set_exempt(uids: &[u32]) -> bool {
    if uids.len() > MH_EXEMPT_MAX {
        return false;
    }
    let Some(mut payload) = Payload::new() else {
        return false;
    };
    {
        let buf = payload.buf_mut();
        for (i, uid) in uids.iter().enumerate() {
            let at = i * std::mem::size_of::<u32>();
            buf[at..at + 4].copy_from_slice(&uid.to_ne_bytes());
        }
    }
    payload.send(
        MH_CMD_POLICY,
        uids.len() as u32,
        (uids.len() * std::mem::size_of::<u32>()) as u32,
    )
}

/// Result of one MH_CMD_EVENTS round trip, including why it may be empty.
pub struct Observed {
    pub events: Vec<Observer>,
    /// bit0 armed, bit1 filter installed, bit2 addresses received,
    /// bit3 this call enabled observation, bit4 a callback matched.
    pub flags: u32,
    /// Number of callbacks entered; 0 means the ftrace op never ran.
    pub calls: u32,
    /// True when the LKM was built with the ftrace observer at all.
    pub ftrace_build: bool,
    /// True when the four addresses were accepted through MH_CMD_CONFIG.
    pub addrs: bool,
    /// False when the LKM refused the command (not loaded, version mismatch).
    pub reached: bool,
}

/// The addresses the loader resolved from kallsyms, written next to the module.
/// Parameter passing through init_module() is not reliable on every kernel, so
/// they are also delivered over the key channel before observing starts.
fn read_addrs() -> Option<[u64; 4]> {
    let text = std::fs::read_to_string(crate::moddir::path().join("ftrace-addrs")).ok()?;
    let mut out = [0u64; 4];
    let mut n = 0;
    for line in text.lines() {
        let Some(value) = line.split_whitespace().nth(1) else {
            continue;
        };
        if n == 4 {
            break;
        }
        out[n] = u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()?;
        n += 1;
    }
    (n == 4).then_some(out)
}

fn configure_addrs(addrs: &[u64; 4]) -> bool {
    let Some(mut payload) = Payload::new() else {
        return false;
    };
    {
        let buf = payload.buf_mut();
        for (i, addr) in addrs.iter().enumerate() {
            buf[i * 8..i * 8 + 8].copy_from_slice(&addr.to_le_bytes());
        }
    }
    payload.send(MH_CMD_CONFIG, 4, 32)
}

/// Turn the caller observer on or off and return (and clear) what it collected.
///
/// Enabling is cheap in the kernel: the ftrace probe is already registered at
/// load time, the switch is one atomic read per stat call while active.
pub fn observe_full(on: bool) -> Observed {
    let mut out = Observed {
        events: Vec::new(),
        flags: 0,
        calls: 0,
        ftrace_build: false,
        addrs: false,
        reached: false,
    };
    if on {
        out.addrs = read_addrs().is_some_and(|addrs| configure_addrs(&addrs));
    }
    let Some(mut payload) = Payload::new() else {
        return out;
    };
    if !payload.send_mode(MH_CMD_EVENTS, u32::from(on), 0, 0) {
        return out;
    }
    out.reached = true;
    out.flags = payload.hdr().mode;
    out.calls = payload.hdr().reserved;
    out.ftrace_build = out.flags & 32 != 0;

    let count = (payload.hdr().count as usize).min(MH_EV_MAX);
    let buf = payload.buf_mut();
    out.events = (0..count)
        .map(|i| {
            // SAFETY: the kernel wrote `count` Uevent records at the start of
            // the buffer and Uevent is repr(C) with no padding.
            let ev: Uevent = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(i * std::mem::size_of::<Uevent>())
                    as *const Uevent)
            };
            Observer {
                uid: ev.uid,
                pid: ev.pid,
                op: ev.op,
                count: ev.count,
                comm: ev.comm,
            }
        })
        .collect();
    out
}

pub fn observe(on: bool) -> Vec<Observer> {
    observe_full(on).events
}

const MH_HIT_MAX: usize = 32;

/// Wire layout of `struct mh_uhit`: one (uid, published record) bucket.  The
/// record is referenced by index rather than by path so 32 buckets still fit in
/// the single payload page.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Uhit {
    uid: u32,
    id: u32,
    count: u64,
    comm: [u8; MH_COMM_LEN],
}

/// One caller that actually landed on a mountpoint magic_mount covers.  Unlike
/// an observer event this is a positive match, so it says which path was seen.
#[derive(Clone)]
pub struct Hit {
    pub uid: u32,
    pub count: u64,
    pub path: PathBuf,
    comm: [u8; MH_COMM_LEN],
}

impl Hit {
    /// `comm` is a fixed 16-byte field, not necessarily NUL terminated.
    pub fn comm(&self) -> String {
        let end = self.comm.iter().position(|c| *c == 0).unwrap_or(MH_COMM_LEN);
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }
}

/// Publication order of the mountpoints last handed to the LKM; `mh_uhit.id`
/// is an index into this list.
static RECORDS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Drain the kernel's hit buckets.  `on` re-arms collection after the drain:
/// the first call right after publishing starts it, the report call stops it.
pub fn hits(on: bool) -> Vec<Hit> {
    let Some(mut payload) = Payload::new() else {
        return Vec::new();
    };
    if !payload.send_mode(MH_CMD_HITS, u32::from(on), 0, 0) {
        return Vec::new();
    }
    let records = RECORDS.lock().unwrap_or_else(|e| e.into_inner()).clone();

    let count = (payload.hdr().count as usize).min(MH_HIT_MAX);
    let buf = payload.buf_mut();
    (0..count)
        .map(|i| {
            // SAFETY: the kernel wrote `count` Uhit records at the start of the
            // buffer and Uhit is repr(C) with no padding.
            let hit: Uhit = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr().add(i * std::mem::size_of::<Uhit>()) as *const Uhit
                )
            };
            let path = records.get(hit.id as usize).cloned().unwrap_or_else(|| {
                PathBuf::from(format!("<record {}>", hit.id))
            });
            Hit {
                uid: hit.uid,
                count: hit.count,
                path,
                comm: hit.comm,
            }
        })
        .collect()
}

/// Drain the observer table, apply the exemption list from the module directory
/// and keep a readable summary.  Called once the boot is over: everything that
/// inspects the mount table has had its chance by then.
pub fn report() -> bool {
    let dir = crate::moddir::path();
    let dir = dir.as_path();
    let mut policy = false;
    let mut exempt_n = 0usize;
    let mut exempt: Vec<u32> = Vec::new();

    if let Ok(text) = std::fs::read_to_string(dir.join("hide-exempt-uids")) {
        exempt = text
            .lines()
            .filter_map(|line| line.split('#').next())
            .filter_map(|line| line.trim().parse().ok())
            .collect();
        exempt_n = exempt.len();
        policy = set_exempt(&exempt);
    }

    // Drain what actually reached a covered mount during boot.  This also
    // stops collection, so it has to happen after every hot lookup has had a
    // chance and before the log is written.
    let touched = hits(false);
    write_hits(dir, &touched, &exempt);

    // Arm once more so the status bits describe a registered probe, take the
    // drain, then tear the trampoline down for good.
    let seen = observe_full(true);
    let _ = observe_full(false);
    let mut log = String::from("# magic_hide observers: uid pid op count comm\n");
    log.push_str(&format!(
        "# ko: {}\n",
        if Path::new("/sys/module/magic_hide").exists() {
            "loaded"
        } else {
            "not loaded"
        }
    ));
    if !seen.reached {
        log.push_str("# state: unavailable (the LKM did not answer MH_CMD_EVENTS)\n");
    } else {
        log.push_str(&format!(
            "# state: ftrace_build={} addrs={} armed={} filtered={} matched={} calls={} events={}\n",
            seen.ftrace_build,
            seen.addrs,
            seen.flags & 1 != 0,
            seen.flags & 2 != 0,
            seen.flags & 16 != 0,
            seen.calls,
            seen.events.len(),
        ));
        log.push_str(&format!(
            "# policy: {} exempt uid(s){}\n",
            exempt_n,
            if policy { "" } else { " (not applied)" }
        ));
    }
    // The loader writes why an insert failed; without it the log only says
    // "not loaded" and the reason stays in a terminal nobody reads.
    if let Ok(text) = std::fs::read_to_string(dir.join("lkm.log")) {
        for line in text.lines().rev().take(20).collect::<Vec<_>>().iter().rev() {
            log.push_str(&format!("# lkm: {line}\n"));
        }
    }
    let mut sorted = seen.events;
    sorted.sort_by(|a, b| b.count.cmp(&a.count));
    for o in &sorted {
        log.push_str(&format!(
            "{} {} {} {} {}\n",
            o.uid,
            o.pid,
            o.op_name(),
            o.count,
            o.comm()
        ));
    }
    let _ = std::fs::write(dir.join("hide-events.log"), log);

    if !sorted.is_empty() {
        log::info!("magic_hide saw {} distinct callers", sorted.len());
    }
    policy || !sorted.is_empty() || !touched.is_empty()
}

/// Keep the per-mount hit table and turn the uids that repeatedly landed on a
/// covered mount into a *suggestion*.  The exemption list is never rewritten
/// here: the operator copies the lines they trust, so a mis-detection cannot
/// silently un-hide a partition for an app.
fn write_hits(dir: &Path, touched: &[Hit], exempt: &[u32]) {
    let mut sorted = touched.to_vec();
    sorted.sort_by(|a, b| b.count.cmp(&a.count));

    let mut log = String::from("# magic_hide hits: uid mount count comm\n");
    for h in &sorted {
        log.push_str(&format!(
            "{} {} {} {}\n",
            h.uid,
            h.path.display(),
            h.count,
            h.comm()
        ));
    }
    let _ = std::fs::write(dir.join("hide-hits.log"), log);

    // Only uids that clearly belong to apps and were seen more than once are
    // worth suggesting: a single lookup is usually a probe that should stay
    // hidden, while uid 0 / system uids must keep the faked view.
    let mut sugg: Vec<(u32, u64)> = Vec::new();
    for h in &sorted {
        if h.uid < 10000 || h.uid == u32::MAX || exempt.contains(&h.uid) || h.count < 3 {
            continue;
        }
        match sugg.iter_mut().find(|(uid, _)| *uid == h.uid) {
            Some((_, count)) => *count += h.count,
            None => sugg.push((h.uid, h.count)),
        }
    }
    sugg.sort_by(|a, b| b.1.cmp(&a.1));

    let mut draft = String::from(
        "# magic_hide suggestion: app uids seen on covered mounts (>= 3 times).\n\
         # Copy a line into hide-exempt-uids to stop hiding from that uid; nothing is applied automatically.\n",
    );
    for (uid, count) in &sugg {
        draft.push_str(&format!("{uid} # seen {count} times\n"));
    }
    let _ = std::fs::write(dir.join("hide-exempt-uids.suggested"), draft);
    if !sugg.is_empty() {
        log::info!("magic_hide hit table suggests {} exempt uid(s)", sugg.len());
    }
}

/// The payload page handed to the kernel.  `get_user_pages_fast()` works on
/// page boundaries, so the buffer has to be page aligned.
struct Payload {
    ptr: *mut u8,
}

impl Payload {
    fn new() -> Option<Self> {
        let layout = std::alloc::Layout::from_size_align(MH_PAGE_SIZE, MH_PAGE_SIZE).ok()?;
        // SAFETY: layout is valid (non-zero size, power-of-two alignment).
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return None;
        }
        Some(Self { ptr })
    }

    fn hdr(&mut self) -> &mut Uhdr {
        // SAFETY: the page was allocated with at least MH_PAGE_SIZE bytes and
        // Uhdr is the first field of the payload.
        unsafe { &mut *(self.ptr as *mut Uhdr) }
    }

    fn buf_mut(&mut self) -> &mut [u8] {
        let off = std::mem::size_of::<Uhdr>();
        // SAFETY: `off + MH_BUF_MAX == MH_PAGE_SIZE`, checked above.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.add(off), MH_BUF_MAX) }
    }

    /// Zero the page, fill the header and hand it to the LKM.  Returns false
    /// when the module is not loaded or the command was rejected.
    fn send(&mut self, cmd: u32, count: u32, data_size: u32) -> bool {
        let mode = if cmd == MH_CMD_MODE { MH_MODE_ALL } else { 0 };
        self.send_mode(cmd, mode, count, data_size)
    }

    fn send_mode(&mut self, cmd: u32, mode: u32, count: u32, data_size: u32) -> bool {
        let hdr = self.hdr();
        hdr.magic = MH_PAYLOAD_MAGIC;
        hdr.version = MH_PAYLOAD_VERSION;
        hdr.cmd = cmd;
        hdr.mode = mode;
        hdr.status = 0;
        hdr.count = count;
        hdr.data_size = data_size;
        hdr.reserved = 0;

        let addr = self.ptr as u64;
        let key_type = c"mh_sync";
        let key_desc = c"sync";
        // SAFETY: `key_type`/`key_desc` are NUL-terminated static strings and
        // `addr` points at a live page in this process' address space.
        let ret = unsafe {
            libc::syscall(
                SYS_ADD_KEY,
                key_type.as_ptr(),
                key_desc.as_ptr(),
                &addr as *const u64,
                std::mem::size_of::<u64>() as libc::c_ulong,
                -1 as libc::c_int,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ECANCELED) {
                // ECANCELED is the designed answer; anything else means the
                // module (or the key type) is not there.  Say it once.
                static ONCE: AtomicBool = AtomicBool::new(false);
                if !ONCE.swap(true, Ordering::Relaxed) {
                    log::info!("magic_hide unavailable: {err}");
                }
                return false;
            }
        }

        // The kernel wrote the result back into the same page.
        let status = self.hdr().status;
        if status != 0 {
            log::warn!("magic_hide command {cmd} failed: {status}");
            return false;
        }
        true
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(MH_PAGE_SIZE, MH_PAGE_SIZE).unwrap();
        // SAFETY: allocated with the same layout in `new()`.
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

#[cfg(target_arch = "aarch64")]
const SYS_ADD_KEY: libc::c_long = 217;
#[cfg(target_arch = "x86_64")]
const SYS_ADD_KEY: libc::c_long = 248;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("magic_hide: unsupported architecture");

fn to_bytes(rec: &Urec) -> [u8; std::mem::size_of::<Urec>()] {
    // SAFETY: Urec is repr(C) and the output array has exactly its size.
    unsafe { std::mem::transmute_copy(rec) }
}

/// Sample the filesystem identity of `path`, or of the closest ancestor that
/// exists.  Used only when the mountinfo snapshot could not be read.
fn sample(path: &Path) -> Option<Native> {
    let mut cur = path.to_path_buf();

    loop {
        let Ok(c_path) = CString::new(cur.as_os_str().as_bytes()) else {
            return None;
        };
        let mut flags = 0u32;
        let mut native = Native::default();

        if let Ok(meta) = std::fs::metadata(&cur) {
            native.dev = encode_dev(meta.dev());
            flags |= MH_REC_F_DEV;
        }
        if let Some((f_type, st)) = statfs_sample_c(&c_path) {
            native.f_type = f_type;
            native.st = st;
            flags |= MH_REC_F_TYPE | MH_REC_F_STAT;
        }
        if let Some(m_flags) = statvfs_flags_c(&c_path) {
            native.m_flags = m_flags;
            flags |= MH_REC_F_MFLAGS;
        }

        if flags != 0 {
            native.flags = flags;
            return Some(native);
        }

        match cur.parent() {
            Some(parent) if parent != cur => cur = parent.to_path_buf(),
            _ => return None,
        }
    }
}

/// One `stat()` of the path before it gets covered.  `stat()` follows symlinks,
/// which is what a stock caller would observe too.
struct StockStat {
    ino: u64,
    size: u64,
    blocks: u64,
    nlink: u64,
    is_dir: bool,
}

fn stock_stat(path: &Path) -> Option<StockStat> {
    let meta = std::fs::metadata(path).ok()?;
    Some(StockStat {
        ino: meta.ino(),
        size: meta.size(),
        blocks: meta.blocks(),
        nlink: meta.nlink(),
        is_dir: meta.file_type().is_dir(),
    })
}

/// Plausible inode for a path that has no stock counterpart.  ext4/EROFS keep
/// inode numbers small and sequential, so the value is folded into 23 bits
/// (up to ~8 M, still far below f2fs block addresses); collisions stay
/// negligible at a few thousand files and the value is stable across boots.
fn synth_ino(path: &Path) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in path.as_os_str().as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash & 0x7f_ffff) | 1
}

/// Read `/proc/self/mountinfo` once.  Each entry keeps the device number from
/// its `major:minor` field, the `f_type` and block accounting `statfs()` reports
/// on that mountpoint and the per-mount flag word built from its option lists
/// (`statfs().f_flags` is not exposed by `struct statfs` on every libc).
fn snapshot_mounts() -> Vec<MountEntry> {
    let mut mounts = Vec::new();
    let Ok(data) = std::fs::read("/proc/self/mountinfo") else {
        return mounts;
    };
    for line in data.split(|&c| c == b'\n') {
        let mut fields = line.split(|&c| c == b' ');
        let (Some(_id), Some(_parent), Some(majmin), Some(_root), Some(point), Some(opts)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let Some(dev) = parse_major_minor(majmin) else {
            continue;
        };
        let point = unescape(point);
        if point.is_empty() {
            continue;
        }

        // After the optional fields comes "-", then fstype, source and the
        // superblock options; only the superblock contributes sync/mand.
        let mut m_flags = flags_from_opts(opts);
        for tok in fields.by_ref() {
            if tok.len() == 1 && tok[0] == b'-' {
                break;
            }
        }
        let _fstype = fields.next();
        let _source = fields.next();
        if let Some(super_opts) = fields.next() {
            m_flags |= flags_from_opts(super_opts) & (ST_SYNCHRONOUS | ST_MANDLOCK);
        }

        mounts.push(MountEntry {
            point,
            dev,
            f_type: None,
            m_flags,
            st: None,
        });
    }
    for m in &mut mounts {
        if let Some((f_type, st)) = statfs_sample_bytes(&m.point) {
            m.f_type = Some(f_type);
            m.st = Some(st);
        }
        // statvfs() is the portable way to read the kernel-computed flag
        // word: it carries exactly what statfs().f_flags would report.
        if let Some(flags) = statvfs_flags_bytes(&m.point) {
            m.m_flags = flags;
        }
    }
    mounts
}

/// The deepest pre-existing mount whose mountpoint contains `path`.
fn covering_mount<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    let bytes = path.as_os_str().as_bytes();
    let mut best: Option<&MountEntry> = None;

    for m in mounts {
        if !is_under(&m.point, bytes) {
            continue;
        }
        // Equal-length match: keep the later entry, which is the topmost
        // mount when several mounts share one mountpoint.
        if let Some(b) = best {
            if b.point.len() >= m.point.len() {
                continue;
            }
        }
        best = Some(m);
    }
    best
}

fn is_under(point: &[u8], path: &[u8]) -> bool {
    if point == b"/" {
        return true;
    }
    if path.len() < point.len() || &path[..point.len()] != point {
        return false;
    }
    path.len() == point.len() || path[point.len()] == b'/'
}

/// `major:minor` as printed by mountinfo, re-encoded the way the kernel stores
/// a `dev_t` in `kstat`/`statfs` (`(major << 20) | minor`).
fn parse_major_minor(field: &[u8]) -> Option<u64> {
    let mut it = field.split(|&c| c == b':');
    let major: u64 = it.next()?.parse_num()?;
    let minor: u64 = it.next()?.parse_num()?;
    if it.next().is_some() {
        return None;
    }
    Some((major << 20) | minor)
}

trait ParseNum {
    fn parse_num(&self) -> Option<u64>;
}

impl ParseNum for [u8] {
    fn parse_num(&self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let mut value = 0u64;
        for &c in self {
            if !c.is_ascii_digit() {
                return None;
            }
            value = value * 10 + (c - b'0') as u64;
        }
        Some(value)
    }
}

/// Decode the octal escapes mountinfo uses for spaces, tabs, newlines and
/// backslashes inside path names.
fn unescape(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\'
            && i + 3 < src.len()
            && src[i + 1].is_ascii_digit()
            && src[i + 2].is_ascii_digit()
            && src[i + 3].is_ascii_digit()
            && src[i + 1] <= b'7'
            && src[i + 2] <= b'7'
            && src[i + 3] <= b'7'
        {
            out.push(
                (src[i + 1] - b'0') * 64 + (src[i + 2] - b'0') * 8 + (src[i + 3] - b'0'),
            );
            i += 4;
        } else {
            out.push(src[i]);
            i += 1;
        }
    }
    out
}

/// Build the `statfs().f_flags` word from one comma-separated option list.
fn flags_from_opts(opts: &[u8]) -> u32 {
    let mut flags = 0u32;

    for opt in opts.split(|&c| c == b',') {
        flags |= match opt {
            b"ro" => ST_RDONLY,
            b"nosuid" => ST_NOSUID,
            b"nodev" => ST_NODEV,
            b"noexec" => ST_NOEXEC,
            b"sync" => ST_SYNCHRONOUS,
            b"mand" => ST_MANDLOCK,
            b"noatime" => ST_NOATIME,
            b"nodiratime" => ST_NODIRATIME,
            b"relatime" => ST_RELATIME,
            _ => 0,
        };
    }
    flags
}

fn statfs_sample_bytes(path: &[u8]) -> Option<(u64, Ustatfs)> {
    let path = CString::new(path).ok()?;
    statfs_sample_c(&path)
}

fn statvfs_flags_bytes(path: &[u8]) -> Option<u32> {
    let path = CString::new(path).ok()?;
    statvfs_flags_c(&path)
}

/// One `statfs()` call yields both the magic and the block accounting that a
/// skeleton mount has to mirror.
fn statfs_sample_c(path: &CString) -> Option<(u64, Ustatfs)> {
    // SAFETY: `path` is a valid path string and `buf` is a live, initialised
    // statfs structure.
    unsafe {
        let mut buf: libc::statfs = std::mem::zeroed();
        if libc::statfs(path.as_ptr(), &mut buf) != 0 {
            return None;
        }
        // fsid_t is a wrapper around `int val[2]` (asm-generic/statfs.h); read
        // it as that array because libc keeps the field private.
        let fsid: [i32; 2] = std::mem::transmute_copy(&buf.f_fsid);
        let st = Ustatfs {
            f_bsize: buf.f_bsize as u64,
            f_blocks: buf.f_blocks as u64,
            f_bfree: buf.f_bfree as u64,
            f_bavail: buf.f_bavail as u64,
            f_files: buf.f_files as u64,
            f_ffree: buf.f_ffree as u64,
            f_namelen: buf.f_namelen as u64,
            f_frsize: buf.f_frsize as u64,
            f_fsid: (fsid[0] as u32 as u64) | ((fsid[1] as u32 as u64) << 32),
        };
        Some((buf.f_type as u64, st))
    }
}

fn statvfs_flags_c(path: &CString) -> Option<u32> {
    // SAFETY: `path` is a valid path string and `buf` is a live, initialised
    // statvfs structure.
    unsafe {
        let mut buf: libc::statvfs = std::mem::zeroed();
        (libc::statvfs(path.as_ptr(), &mut buf) == 0).then_some(buf.f_flag as u32)
    }
}

/// glibc's gnu_dev_major()/gnu_dev_minor(), re-encoded the way the kernel
/// stores a `dev_t` in `kstat` (new_encode_dev).
fn encode_dev(dev: u64) -> u64 {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfffu64);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xffu64);
    (major << 20) | minor
}
