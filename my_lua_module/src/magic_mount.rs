use crate::defs::{DISABLE_FILE_NAME, MODULE_DIR, SKIP_MOUNT_FILE_NAME};
use crate::hide::{
    MIRROR_FLAGS_MASK, MountTable, ST_NODEV, ST_NOEXEC, ST_NOSUID, ST_RDONLY,
};
use crate::magic_mount::NodeFileType::{Directory, RegularFile, Symlink, Whiteout};
use crate::parallel::par_map;
use crate::restorecon::{lgetfilecon, lsetfilecon};
use crate::utils::get_work_dir;
use crate::utils::ensure_dir_exists;
use anyhow::{Context, Result, bail};
use extattr::lgetxattr;
use rustix::fs::{
    Gid, MetadataExt, Mode, MountFlags, MountPropagationFlags, Uid, UnmountFlags, bind_mount,
    chmod, chown, mount, move_mount, unmount,
};
use rustix::mount::mount_change;
use rustix::path::Arg;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs;
use std::fs::{FileType, create_dir, create_dir_all, read_link};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::{Path, PathBuf};

const REPLACE_DIR_XATTR: &str = "trusted.overlay.opaque";

/// Directory inside the workspace that holds the read-only clone of the module
/// tree.  Every module file is bound from here, so the resulting mount inherits
/// `MNT_READONLY` from the clone instead of paying one remount per file.
const MODULE_VIEW: &str = "modules-ro";

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum NodeFileType {
    RegularFile,
    Directory,
    Symlink,
    Whiteout,
}

impl NodeFileType {
    fn from_file_type(file_type: FileType) -> Option<Self> {
        if file_type.is_file() {
            Some(RegularFile)
        } else if file_type.is_dir() {
            Some(Directory)
        } else if file_type.is_symlink() {
            Some(Symlink)
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct Node {
    name: String,
    file_type: NodeFileType,
    children: HashMap<String, Node>,
    // the module that owned this node
    module_path: Option<PathBuf>,
    replace: bool,
    skip: bool,
}

impl Node {
    fn collect_module_files<T: AsRef<Path>>(&mut self, module_dir: T) -> Result<bool> {
        let dir = module_dir.as_ref();
        let mut has_file = false;
        for entry in dir.read_dir()?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            let node = match self.children.entry(name.clone()) {
                Entry::Occupied(o) => Some(o.into_mut()),
                Entry::Vacant(v) => Self::new_module(&name, &entry).map(|it| v.insert(it)),
            };

            if let Some(node) = node {
                has_file |= if node.file_type == Directory {
                    node.collect_module_files(dir.join(&node.name))? || node.replace
                } else {
                    true
                }
            }
        }

        Ok(has_file)
    }

    fn new_root<T: ToString>(name: T) -> Self {
        Node {
            name: name.to_string(),
            file_type: Directory,
            children: Default::default(),
            module_path: None,
            replace: false,
            skip: false,
        }
    }

    fn new_module<T: ToString>(name: T, entry: &std::fs::DirEntry) -> Option<Self> {
        if let Ok(metadata) = entry.metadata() {
            let path = entry.path();
            let file_type = if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
                Some(Whiteout)
            } else {
                NodeFileType::from_file_type(metadata.file_type())
            };
            if let Some(file_type) = file_type {
                let mut replace = false;
                if file_type == Directory {
                    if let Ok(v) = lgetxattr(&path, REPLACE_DIR_XATTR) {
                        if String::from_utf8_lossy(&v) == "y" {
                            replace = true;
                        }
                    }
                }
                return Some(Node {
                    name: name.to_string(),
                    file_type,
                    children: Default::default(),
                    module_path: Some(path),
                    replace,
                    skip: false,
                });
            }
        }

        None
    }

    /// Point every collected module path at the read-only clone of the module
    /// tree.  Nothing else reads these paths except the bind/symlink creation.
    fn rebase_module_paths(&mut self, from: &Path, to: &Path) {
        if let Some(path) = &self.module_path {
            if let Ok(suffix) = path.strip_prefix(from) {
                self.module_path = Some(to.join(suffix));
            }
        }
        for child in self.children.values_mut() {
            child.rebase_module_paths(from, to);
        }
    }
}

/// Merge a tree collected from one module into the tree collected from the
/// previous ones.  The first module that defined a path keeps its metadata,
/// directories are merged recursively - the same precedence the sequential
/// collector had.
fn merge_node(dst: &mut Node, src: Node) {
    for (name, child) in src.children {
        match dst.children.entry(name) {
            Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                if existing.file_type == Directory && child.file_type == Directory {
                    merge_node(existing, child);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(child);
            }
        }
    }
}

fn collect_module_files() -> Result<Option<Node>> {
    let mut root = Node::new_root("");
    let mut system = Node::new_root("system");
    let module_root = Path::new(MODULE_DIR);

    // Figure out which modules take part first (cheap stat calls), then scan
    // their `system/` trees in parallel: xattr reads and metadata lookups
    // dominate the scan on modules with thousands of files.
    let mut candidates = Vec::new();
    for entry in module_root.read_dir()?.flatten() {
        if !entry.file_type()?.is_dir() {
            continue;
        }

        if entry.path().join(DISABLE_FILE_NAME).exists()
            || entry.path().join(SKIP_MOUNT_FILE_NAME).exists()
        {
            continue;
        }

        let mod_system = entry.path().join("system");
        if !mod_system.is_dir() {
            continue;
        }

        log::debug!("collecting {}", entry.path().display());
        candidates.push(mod_system);
    }

    let scanned = par_map(candidates, |mod_system| -> Result<(Node, bool)> {
        let mut tree = Node::new_root("system");
        let has_file = tree.collect_module_files(&mod_system)?;
        Ok((tree, has_file))
    });

    let mut has_file = false;
    for result in scanned {
        let (tree, found) = result?;
        has_file |= found;
        merge_node(&mut system, tree);
    }

    if has_file {
        for (partition, require_symlink) in [
            ("vendor", true),
            ("system_ext", true),
            ("product", true),
            ("odm", false),
            ("oem", false),
        ] {
            let path_of_root = Path::new("/").join(partition);
            let path_of_system = Path::new("/system").join(partition);
            if path_of_root.is_dir() && (!require_symlink || path_of_system.is_symlink()) {
                let name = partition.to_string();
                if let Some(node) = system.children.remove(&name) {
                    root.children.insert(name, node);
                }
            }
        }
        root.children.insert("system".to_string(), system);
        Ok(Some(root))
    } else {
        Ok(None)
    }
}

fn clone_symlink<Src: AsRef<Path>, Dst: AsRef<Path>>(src: Src, dst: Dst) -> Result<()> {
    let src_symlink = read_link(src.as_ref())?;
    symlink(&src_symlink, dst.as_ref())?;
    lsetfilecon(dst.as_ref(), lgetfilecon(src.as_ref())?.as_str())?;
    log::debug!(
        "clone symlink {} -> {}({})",
        dst.as_ref().display(),
        dst.as_ref().display(),
        src_symlink.display()
    );
    Ok(())
}

/// One unit of mount work inside a directory.  Both variants own their
/// inputs, so they can be handed to a worker thread.
enum Job {
    Node(Node),
    Mirror { src: PathBuf, dst: PathBuf },
}

fn mount_mirror(src: &Path, dst: &Path) -> Result<()> {
    let file_type = src.symlink_metadata()?.file_type();

    if file_type.is_file() {
        log::debug!("mount mirror file {} -> {}", src.display(), dst.display());
        fs::File::create(dst)?;
        bind_mount(src, dst)?;
    } else if file_type.is_dir() {
        // One recursive bind covers the whole subtree: the kernel keeps the
        // original inodes, labels, flags and even sub-mounts, and the count of
        // mounts stops growing with the number of files inside.
        log::debug!("mount mirror dir {} -> {}", src.display(), dst.display());
        create_dir(dst)?;
        bind_recursive(src, dst)
            .with_context(|| format!("mirror dir {} -> {}", src.display(), dst.display()))?;
    } else if file_type.is_symlink() {
        log::debug!("create mirror symlink {} -> {}", src.display(), dst.display());
        clone_symlink(src, dst)?;
    }

    Ok(())
}

/// `MS_BIND | MS_REC`: clone the source mount tree instead of only its top
/// dentry, so sub-mounts that belong to other modules stay visible.
fn bind_recursive(src: &Path, dst: &Path) -> Result<()> {
    let src_c = std::ffi::CString::new(src.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("path contains NUL: {}", src.display()))?;
    let dst_c = std::ffi::CString::new(dst.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("path contains NUL: {}", dst.display()))?;

    // SAFETY: both strings are NUL terminated; `MS_BIND | MS_REC` takes no
    // filesystem type or data.
    let ret = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind recursive {} -> {}", src.display(), dst.display()));
    }
    Ok(())
}

/* Per-mount attributes of mount_setattr(2) (include/uapi/linux/mount.h). */
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
const AT_RECURSIVE: libc::c_int = 0x0000_8000;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Copy the per-mount flags of the mount we cover onto the mount we just
/// created.
///
/// Stock Android keeps `/system`, `/vendor`, ... on EROFS mounts that are
/// `ro`, so a write through those paths fails with EROFS.  Our skeleton is a
/// rw tmpfs and module files are bind mounts of `/data`, both of which would
/// silently accept the write (the module file case writes through to the real
/// module directory).  `recursive` uses `mount_setattr(AT_RECURSIVE)` so the
/// whole subtree - including every file bind inside a skeleton - is changed in
/// one syscall.  Kernels before 5.12 have no mount_setattr, so the fall back
/// remounts the top mount only, which still covers the mountpoint itself.
fn mirror_mount_flags(path: &Path, flags: u32, recursive: bool) -> std::io::Result<()> {
    // Only RDONLY/NOSUID/NODEV/NOEXEC can be expressed as mount_setattr
    // attributes; the atime and sync bits are left to the remount fallback.
    let wanted = flags & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC);
    let mut attr_set = 0u64;
    if wanted & ST_RDONLY != 0 {
        attr_set |= MOUNT_ATTR_RDONLY;
    }
    if wanted & ST_NOSUID != 0 {
        attr_set |= MOUNT_ATTR_NOSUID;
    }
    if wanted & ST_NODEV != 0 {
        attr_set |= MOUNT_ATTR_NODEV;
    }
    if wanted & ST_NOEXEC != 0 {
        attr_set |= MOUNT_ATTR_NOEXEC;
    }
    // A bind of a module file inherits /data's nosuid/nodev while the covered
    // /system mount has neither, so the unwanted bits have to be cleared too.
    let all = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;
    let attr_clr = all & !attr_set;

    if let Ok(()) = set_mount_attr(path, attr_set, attr_clr, recursive) {
        return Ok(());
    }

    // MS_REMOUNT|MS_BIND replaces the complete per-mount word without
    // touching the superblock, so hand it every mirrored bit (atime included).
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mflags = (flags & MIRROR_FLAGS_MASK) as libc::c_ulong | libc::MS_BIND | libc::MS_REMOUNT;
    // SAFETY: `path_c` is a NUL-terminated path; a remount bind passes neither
    // a filesystem type nor data.
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            path_c.as_ptr(),
            std::ptr::null(),
            mflags,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_mount_attr(
    path: &Path,
    attr_set: u64,
    attr_clr: u64,
    recursive: bool,
) -> std::io::Result<()> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let attr = MountAttr {
        attr_set,
        attr_clr,
        propagation: 0,
        userns_fd: 0,
    };
    let flags = if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: `path_c` is NUL terminated, `attr` outlives the call and the
    // kernel only reads `size_of::<MountAttr>()` bytes from it.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            path_c.as_ptr(),
            flags,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Mirror the covered mount's flags on `path`; a failure is logged instead of
/// aborting, because the LKM still forges `statfs().f_flags` for `path`.
fn mirror_covered_flags(path: &Path, mounts: &MountTable, recursive: bool) {
    let Some(flags) = mounts.native_flags(path) else {
        return;
    };
    if flags & MIRROR_FLAGS_MASK == 0 {
        return;
    }
    log::debug!(
        "mirror flags {:#x} on {} (recursive={recursive})",
        flags & MIRROR_FLAGS_MASK,
        path.display()
    );
    if let Err(e) = mirror_mount_flags(path, flags, recursive) {
        log::error!("failed to mirror flags of {}: {e}", path.display());
    }
}

/// Clone the whole module tree once and make that clone read-only.  A bind of
/// a file taken from a `MNT_READONLY` mount is itself `MNT_READONLY`
/// (`clone_mnt()` copies the per-mount flags), so the thousands of per-file
/// binds cost exactly two extra syscalls in total instead of one each.
/// Returns false when the clone cannot be built; the caller then falls back to
/// mirroring the flags per mount.
fn prepare_module_view(view: &Path) -> bool {
    if create_dir_all(view).is_err() {
        return false;
    }
    if let Err(e) = bind_recursive(Path::new(MODULE_DIR), view) {
        log::error!("cannot clone module tree to {}: {e:#}", view.display());
        return false;
    }
    if let Err(e) = remount_readonly(view) {
        log::error!("cannot make {} read-only: {e}", view.display());
        return false;
    }
    true
}

/// `MS_REMOUNT|MS_BIND` replaces the per-mount flag word without touching the
/// superblock, so the clone keeps `MNT_READONLY` and drops the `nosuid,nodev`
/// inherited from /data.  Unlike mount_setattr this works on every supported
/// kernel, and the clone is a single mount, so no recursion is needed.
fn remount_readonly(path: &Path) -> std::io::Result<()> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `path_c` is a NUL-terminated path; a remount bind passes neither
    // a filesystem type nor data.
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            path_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn do_magic_mount(
    path: &Path,
    work_dir_path: &Path,
    current: Node,
    has_tmpfs: bool,
    mounts: &MountTable,
    module_ro: bool,
) -> Result<()> {
    let mut current = current;
    let path = path.join(&current.name);
    let work_dir_path = work_dir_path.join(&current.name);
    match current.file_type {
        RegularFile => {
            let target_path = if has_tmpfs {
                fs::File::create(&work_dir_path)?;
                &work_dir_path
            } else {
                &path
            };
            if let Some(module_path) = &current.module_path {
                log::debug!(
                    "mount module file {} -> {}",
                    module_path.display(),
                    work_dir_path.display()
                );
                // A bind mount is its own mount, so the LKM needs the native
                // identity of the final path to answer stat()/statfs() with
                // the partition values instead of the module filesystem's.
                mounts.record(&path);
                bind_mount(module_path, target_path)?;
                if !has_tmpfs && !module_ro {
                    // Only when the read-only module clone is unavailable: the
                    // bind is then still rw and needs its own remount.
                    mirror_covered_flags(&path, mounts, false);
                }
            } else {
                bail!("cannot mount root file {}!", path.display());
            }
        }
        Symlink => {
            if let Some(module_path) = &current.module_path {
                log::debug!(
                    "create module symlink {} -> {}",
                    module_path.display(),
                    work_dir_path.display()
                );
                clone_symlink(module_path, &work_dir_path)?;
            } else {
                bail!("cannot mount root symlink {}!", path.display());
            }
        }
        Directory => {
            let mut create_tmpfs = !has_tmpfs && current.replace && current.module_path.is_some();
            if !has_tmpfs && !create_tmpfs {
                for it in &mut current.children {
                    let (name, node) = it;
                    let real_path = path.join(name);
                    let need = match node.file_type {
                        Symlink => true,
                        Whiteout => real_path.exists(),
                        _ => {
                            if let Ok(metadata) = real_path.symlink_metadata() {
                                let file_type = NodeFileType::from_file_type(metadata.file_type())
                                    .unwrap_or(Whiteout);
                                file_type != node.file_type || file_type == Symlink
                            } else {
                                // real path not exists
                                true
                            }
                        }
                    };
                    if need {
                        if current.module_path.is_none() {
                            log::error!(
                                "cannot create tmpfs on {}, ignore: {name}",
                                path.display()
                            );
                            node.skip = true;
                            continue;
                        }
                        create_tmpfs = true;
                        break;
                    }
                }
            }

            let has_tmpfs = has_tmpfs || create_tmpfs;

            if has_tmpfs {
                log::debug!(
                    "creating tmpfs skeleton for {} at {}",
                    path.display(),
                    work_dir_path.display()
                );
                create_dir_all(&work_dir_path)?;
                let (metadata, src) = if path.exists() {
                    (path.metadata()?, path.as_path())
                } else if let Some(module_path) = &current.module_path {
                    (module_path.metadata()?, module_path.as_path())
                } else {
                    bail!("cannot mount root dir {}!", path.display());
                };
                chmod(&work_dir_path, Mode::from_raw_mode(metadata.mode()))?;
                unsafe {
                    chown(
                        &work_dir_path,
                        Some(Uid::from_raw(metadata.uid())),
                        Some(Gid::from_raw(metadata.gid())),
                    )?;
                }
                lsetfilecon(&work_dir_path, lgetfilecon(src)?.as_str())?;
            }

            if create_tmpfs {
                log::debug!(
                    "creating tmpfs for {} at {}",
                    path.display(),
                    work_dir_path.display()
                );
                // The covered directory's real identity has to be sampled
                // before we bind the skeleton over it.
                mounts.record(&path);
                bind_mount(&work_dir_path, &work_dir_path).context("bind self")?;
            }

            let mut jobs: Vec<Job> = Vec::new();

            if path.exists() && !current.replace {
                for entry in path.read_dir()?.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Some(node) = current.children.remove(&name) {
                        if node.skip {
                            continue;
                        }
                        jobs.push(Job::Node(node));
                    } else if has_tmpfs {
                        // Mirroring is only needed inside a tmpfs skeleton:
                        // the real directory has to be reproduced so the
                        // module's entries can be layered on top of it.
                        jobs.push(Job::Mirror {
                            src: path.join(&name),
                            dst: work_dir_path.join(&name),
                        });
                    }
                }
            }

            if current.replace {
                if current.module_path.is_none() {
                    bail!(
                        "dir {} is declared as replaced but it is root!",
                        path.display()
                    );
                } else {
                    log::debug!("dir {} is replaced", path.display());
                }
            }

            for (_, node) in current.children.drain() {
                if node.skip {
                    continue;
                }
                jobs.push(Job::Node(node));
            }

            // Children write to disjoint paths, so they can be mounted in
            // parallel; the tmpfs move below still waits for all of them.
            let results = par_map(jobs, |job| -> Result<()> {
                match job {
                    Job::Node(node) => {
                        let name = node.name.clone();
                        do_magic_mount(&path, &work_dir_path, node, has_tmpfs, mounts, module_ro)
                            .with_context(|| format!("magic mount {}/{name}", path.display()))
                    }
                    Job::Mirror { src, dst } => mount_mirror(&src, &dst)
                        .with_context(|| format!("mount mirror {}", src.display())),
                }
            });

            for result in results {
                if let Err(e) = result {
                    if has_tmpfs {
                        return Err(e);
                    }
                    log::error!("mount child failed: {e:#}");
                }
            }

            if create_tmpfs {
                log::debug!(
                    "moving tmpfs {} -> {}",
                    work_dir_path.display(),
                    path.display()
                );
                move_mount(&work_dir_path, &path).context("move self")?;
                mount_change(&path, MountPropagationFlags::PRIVATE)
                    .context("make self private")?;
                // One recursive call makes the skeleton and every module file
                // bound inside it read-only, like the EROFS mount it covers.
                mirror_covered_flags(&path, mounts, true);
            }
        }
        Whiteout => {
            log::debug!("file {} is removed", path.display());
        }
    }

    Ok(())
}

pub fn mount_tmp(mount_source: &str) -> Result<()> {
    let tmp_dir = PathBuf::from("/debug_ramdisk");
    log::info!("mount_dir: {}", tmp_dir.display());
    mount(
        mount_source,
        &tmp_dir,
        "tmpfs",
        MountFlags::empty(),
        "",
    )
    .context("mount tmp")?;
    mount_change(&tmp_dir, MountPropagationFlags::PRIVATE).context("make tmp private")?;
    Ok(())
}

pub fn magic_mount(mount_source: &str) -> Result<()> {
    match collect_module_files()? {
        Some(root) => {
            log::debug!("collected: {root:#?}");
            // Snapshot the mount table before creating any workspace, so every
            // record describes the state we are about to cover, not ourselves.
            let mounts = MountTable::new();
            let tmp_dir = PathBuf::from(get_work_dir());
            log::info!("mount_dir: {}", tmp_dir.display());
            let ramdisk_tmp = tmp_dir.to_string_lossy().contains("ramdisk");
            if ramdisk_tmp {
                mount_tmp(mount_source)?;
            }
            ensure_dir_exists(&tmp_dir)?;
            mount(
                mount_source,
                &tmp_dir,
                "tmpfs",
                MountFlags::empty(),
                "",
            )
            .context("mount tmp")?;
            mount_change(&tmp_dir, MountPropagationFlags::PRIVATE).context("make tmp private")?;

            // One read-only clone of the module tree: every module file is
            // bound from it, so read-only behaviour is inherited per bind and
            // no per-file mount_setattr/remount is ever issued.
            let module_view = tmp_dir.join(MODULE_VIEW);
            let module_ro = prepare_module_view(&module_view);
            let root = if module_ro {
                let mut root = root;
                root.rebase_module_paths(Path::new(MODULE_DIR), &module_view);
                root
            } else {
                root
            };

            let result =
                do_magic_mount(Path::new("/"), &tmp_dir, root, false, &mounts, module_ro);

            if let Err(e) = unmount(&tmp_dir, UnmountFlags::DETACH) {
                log::error!("failed to unmount tmp {}", e);
            }
            fs::remove_dir(tmp_dir).ok();
            if ramdisk_tmp {
                // mount_tmp() stacked a tmpfs on /debug_ramdisk just so the
                // workdir below it could be created.  Leaving it mounted shows
                // up in every mount table as an extra tmpfs, so detach our
                // layer again (MNT_DETACH only removes the top mount; an
                // earlier framework mount stays below).
                if let Err(e) = unmount("/debug_ramdisk", UnmountFlags::DETACH) {
                    log::error!("failed to unmount tmp /debug_ramdisk: {}", e);
                }
            }

            if result.is_ok() {
                // Hand the final mountpoints and their pre-mount identity to
                // magic_hide.ko, which drops the matching proc lines and
                // answers statfs()/stat() with the covered filesystem.
                mounts.publish();
            }
            result
        }
        _ => {
            log::info!("no modules to mount, skipping!");
            Ok(())
        }
    }
}
