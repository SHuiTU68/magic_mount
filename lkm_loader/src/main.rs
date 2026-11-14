//! Loader and mount supervisor shipped as `lkm/loader`.
//!
//! It does the three things a shell script cannot do safely:
//!
//! * `load` matches this device's KMI against the `.ko` files next to the
//!   binary and inserts the first one the kernel accepts.
//! * `mount` / `refresh` run the native mount pass in a child process with a
//!   deadline, so a panic, a crash or a deadlock costs one boot instead of
//!   looping forever.  Two failed boots in a row make the next one skip the
//!   mount entirely, which is what breaks a boot loop: the device comes up
//!   and the boot after that tries again.
//! * `donor-check` compares the mount table this process sees against a real
//!   namespace with our mounts detached, which is the view a device without
//!   the module would report.
//!
//! The layout is `<module>/lkm/loader`, so the module directory and the .ko
//! directory are both derived from the running executable - nothing here
//! hardcodes /data/adb/modules/magic_mount.

use std::collections::{BTreeMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::FromRawFd;
use std::os::raw::{c_char, c_int, c_long, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};
use std::time::{Duration, Instant};

const SYS_INIT_MODULE: c_long = 105;
const SYS_FINIT_MODULE: c_long = 273;
const SYS_DELETE_MODULE: c_long = 106;
const SYS_MEMFD_CREATE: c_long = 279;
const O_NONBLOCK: c_int = 0o4000;

const MOUNT_DEADLINE: Duration = Duration::from_secs(30);
const REFRESH_DEADLINE: Duration = Duration::from_secs(10);

/// Set from the command line when the binary had to be run from a tmpfs copy:
/// the state files and the .ko lookup then point at the real module tree.
static LKM_DIR_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Exit code meaning "the native library could not be loaded", which tells the
/// caller to fall back to an in-process call instead of treating it as a
/// mount failure.
const EXIT_NO_LIBRARY: i32 = 2;

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

extern "C" {
    fn uname(buf: *mut Utsname) -> c_int;
    fn syscall(num: c_long, ...) -> c_long;
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
}

#[link(name = "dl")]
extern "C" {
    fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let action = args.get(1).map(String::as_str).unwrap_or("load");

    // Set when the binary had to be copied to tmpfs to become executable: its
    // own directory is then /dev, not the module tree.
    if let Ok(dir) = std::env::var("MM_LKM_DIR") {
        if Path::new(&dir).is_dir() {
            let _ = LKM_DIR_OVERRIDE.set(PathBuf::from(dir));
        }
    }

    match action {
        "load" => load(),
        "mount" => supervise("__mount", args.get(2).map(String::as_str).unwrap_or("APatch"), MOUNT_DEADLINE),
        "refresh" => supervise("__refresh", "", REFRESH_DEADLINE),
        "status" => status(),
        "unload" => unload(),
        "donor-check" => donor_check(),
        "bench" => bench(),
        "__mount" => run_native("magic_mount_exec", args.get(2).map(String::as_str).unwrap_or("APatch")),
        "__refresh" => run_native("refresh_hide_exec", ""),
        "__donor-view" => donor_view(),
        other => {
            eprintln!("usage: loader [load|mount <source>|refresh|status|unload|donor-check|bench [n]] (got {other})");
            exit(64);
        }
    }
}

// ---------------------------------------------------------------- paths

fn lkm_dir() -> PathBuf {
    if let Some(dir) = LKM_DIR_OVERRIDE.get() {
        return dir.clone();
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("/data/adb/modules/magic_mount/lkm"))
}

/// Where the .ko files may live.  A metamodule is installed twice - once under
/// /data/adb/modules/<id> for the manager and once under /data/adb/metamodule -
/// and the two copies are not always populated the same way, so a .ko missing
/// from one tree is still usable from the other.
fn scan_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        lkm_dir(),
        PathBuf::from("/data/adb/metamodule/lkm"),
        PathBuf::from("/data/adb/modules/magic_mount/lkm"),
    ];
    dirs.dedup();
    dirs.retain(|d| d.is_dir());
    dirs
}

fn module_dir() -> PathBuf {
    lkm_dir().parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/data/adb/modules/magic_mount"))
}

fn library() -> PathBuf {
    module_dir().join("libmagic_mount.so")
}

fn failures_file() -> PathBuf {
    module_dir().join("mount-failures")
}

fn stats_file() -> PathBuf {
    module_dir().join("mount-stats.txt")
}

// ---------------------------------------------------------------- helpers

fn release() -> String {
    unsafe {
        let mut uts: Utsname = std::mem::zeroed();
        if uname(&mut uts) != 0 {
            return String::new();
        }
        let bytes: Vec<u8> = uts.release.iter().copied().take_while(|b| *b != 0).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn property(name: &str) -> String {
    let Ok(key) = CString::new(name) else {
        return String::new();
    };
    // c_char is u8 on aarch64-linux-android, i8 elsewhere; the buffer follows
    // the target, the string conversion goes through bytes.
    let mut buf = [0 as c_char; 92];
    let len = unsafe { __system_property_get(key.as_ptr(), buf.as_mut_ptr()) };
    if len <= 0 {
        return String::new();
    }
    let bytes: Vec<u8> = buf.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn loaded() -> bool {
    Path::new("/sys/module/magic_hide").exists()
        || fs::read_to_string("/proc/modules")
            .map(|text| text.lines().any(|l| l.starts_with("magic_hide ")))
            .unwrap_or(false)
}

fn read_count(path: &Path) -> u32 {
    fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

fn write_count(path: &Path, value: u32) {
    let _ = fs::write(path, value.to_string());
}

/// "5.15.148-android13-8-g..." -> ("android13", "5.15")
fn release_info(rel: &str) -> (Option<String>, Option<String>) {
    let first = rel.split(['-', '_']).next().unwrap_or("");
    let mut parts = first.split('.');
    let version = match (parts.next(), parts.next()) {
        (Some(a), Some(b))
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_digit()) && !b.is_empty() && b.chars().all(|c| c.is_ascii_digit()) =>
        {
            Some(format!("{a}.{b}"))
        }
        _ => None,
    };
    let tag = rel
        .split(['-', '_', '.'])
        .find(|part| {
            part.len() > 7
                && part.starts_with("android")
                && part[7..].chars().all(|c| c.is_ascii_digit())
        })
        .map(str::to_string);
    (tag, version)
}

fn family(version: &str) -> &'static [&'static str] {
    match version {
        "5.10" => &["android12-5.10", "android13-5.10"],
        "5.15" => &["android13-5.15", "android14-5.15"],
        "6.1" => &["android14-6.1"],
        "6.6" => &["android15-6.6"],
        "6.12" => &["android16-6.12"],
        _ => &[],
    }
}

fn candidates() -> Vec<PathBuf> {
    let rel = release();
    let (tag, version) = release_info(&rel);
    let platform = property("ro.build.version.release");
    let platform_tag = {
        let head = platform.split('.').next().unwrap_or("");
        if !head.is_empty() && head.chars().all(|c| c.is_ascii_digit()) {
            Some(format!("android{head}"))
        } else {
            None
        }
    };

    let mut names: Vec<String> = Vec::new();
    if let (Some(tag), Some(version)) = (&tag, &version) {
        names.push(format!("{tag}-{version}"));
    }
    if let (Some(tag), Some(version)) = (&platform_tag, &version) {
        names.push(format!("{tag}-{version}"));
    }
    if let Some(version) = &version {
        names.extend(family(version).iter().map(|s| s.to_string()));
    }

    let dirs = scan_dirs();
    let mut shipped: Vec<String> = Vec::new();
    for dir in &dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for name in entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
        {
            if name.starts_with("magic_hide")
                && name.ends_with(".ko")
                && !shipped.contains(&name)
            {
                shipped.push(name);
            }
        }
    }

    if let Some(version) = &version {
        // Anything built for the same kernel line is still worth a try.
        names.extend(
            shipped
                .iter()
                .filter(|n| n.contains(&format!("-{version}.ko")))
                .map(|n| n.trim_start_matches("magic_hide-").trim_end_matches(".ko").to_string()),
        );
    }
    names.push("magic_hide".to_string());

    let mut out: Vec<PathBuf> = Vec::new();
    for name in names {
        for dir in &dirs {
            for candidate in [format!("magic_hide-{name}.ko"), format!("{name}.ko")] {
                let path = dir.join(candidate);
                if path.exists() && !out.contains(&path) {
                    out.push(path);
                }
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

// ------------------------------------------------------- module image fix-ups
//
// A GKI kernel loads a .ko only when every undefined symbol is exported by
// another loaded module or by the kernel's ksymtab, and only when vermagic
// matches the running build byte for byte.  Both are refused with a single
// "Unknown symbol in module" / "version magic ... should be ..." line, which is
// why the loader patches the image instead of asking the user to rebuild:
//
//   * undefined symbols present in kallsyms are written in as absolute values
//     (the trick lkmloader and KernelSU's manual mode use), so a function that
//     is not exported but is present can still be called;
//   * on a vermagic mismatch the kernel prints what it expects, so the string
//     in .modinfo is rewritten and the insert retried.

fn rd16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn rd32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        u64::from_le_bytes(a)
    })
}

fn wr16(b: &mut [u8], o: usize, v: u16) {
    if let Some(s) = b.get_mut(o..o + 2) {
        s.copy_from_slice(&v.to_le_bytes());
    }
}

fn wr64(b: &mut [u8], o: usize, v: u64) {
    if let Some(s) = b.get_mut(o..o + 8) {
        s.copy_from_slice(&v.to_le_bytes());
    }
}

fn cstr(buf: &[u8], off: usize) -> String {
    let Some(rest) = buf.get(off..) else {
        return String::new();
    };
    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

#[derive(Clone, Copy)]
struct Sections {
    shoff: usize,
    entsize: usize,
    num: usize,
}

impl Sections {
    fn parse(buf: &[u8]) -> Option<Self> {
        let shoff = rd64(buf, 0x28)? as usize;
        let entsize = rd16(buf, 0x3a)? as usize;
        let num = rd16(buf, 0x3c)? as usize;
        if entsize < 64 || num == 0 || shoff.checked_add(entsize * num)? > buf.len() {
            return None;
        }
        Some(Self { shoff, entsize, num })
    }

    fn at(&self, i: usize) -> usize {
        self.shoff + i * self.entsize
    }

    fn offset(&self, buf: &[u8], i: usize) -> usize {
        rd64(buf, self.at(i) + 24).unwrap_or(0) as usize
    }

    fn size(&self, buf: &[u8], i: usize) -> usize {
        rd64(buf, self.at(i) + 32).unwrap_or(0) as usize
    }

    fn sh_type(&self, buf: &[u8], i: usize) -> u32 {
        rd32(buf, self.at(i) + 4).unwrap_or(0)
    }

    fn link(&self, buf: &[u8], i: usize) -> usize {
        rd32(buf, self.at(i) + 40).unwrap_or(0) as usize
    }

    fn name(&self, buf: &[u8], i: usize) -> String {
        let shstrndx = rd16(buf, 0x3e).unwrap_or(0) as usize;
        let strtab = self.offset(buf, shstrndx);
        let name_off = rd32(buf, self.at(i)).unwrap_or(0) as usize;
        cstr(buf, strtab + name_off)
    }
}

/// kallsyms as name -> address.  kptr_restrict is lowered around the read:
/// root on Android does not always hold CAP_SYSLOG, and the sysctl is
/// writable from exactly the context that is allowed to load a module.
fn kallsyms() -> std::collections::HashMap<String, u64> {
    const KPTR: &str = "/proc/sys/kernel/kptr_restrict";
    let saved = fs::read_to_string(KPTR).ok();
    let was = saved.as_deref().map(str::trim).unwrap_or("0").to_string();
    if was != "0" {
        let _ = fs::write(KPTR, "0\n");
    }
    let text = fs::read_to_string("/proc/kallsyms").unwrap_or_default();
    if was != "0" {
        let _ = fs::write(KPTR, format!("{was}\n"));
    }

    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(_ty), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if let Ok(value) = u64::from_str_radix(addr, 16) {
            if value != 0 {
                map.insert(name.to_string(), value);
            }
        }
    }
    map
}

/// Bind every undefined symbol that kallsyms knows to its runtime address.
/// The kernel then treats it as an absolute value and skips the export check.
fn resolve_undef(buf: &mut [u8], syms: &std::collections::HashMap<String, u64>) -> (usize, usize) {
    let Some(secs) = Sections::parse(buf) else {
        return (0, 0);
    };
    let (mut resolved, mut undef) = (0usize, 0usize);

    for i in 0..secs.num {
        if secs.sh_type(buf, i) != 2 {
            continue; // SHT_SYMTAB
        }
        let off = secs.offset(buf, i);
        let size = secs.size(buf, i);
        let strtab = secs.offset(buf, secs.link(buf, i));
        for j in 0..size / 24 {
            let s = off + j * 24;
            if rd16(buf, s + 6) != Some(0) {
                continue; // not SHN_UNDEF
            }
            let name = cstr(buf, strtab + rd32(buf, s).unwrap_or(0) as usize);
            if name.is_empty() {
                continue;
            }
            undef += 1;
            if let Some(&addr) = syms.get(&name) {
                wr64(buf, s + 8, addr);
                wr16(buf, s + 6, 0xfff1); // SHN_ABS
                resolved += 1;
            }
        }
    }
    (resolved, undef)
}

/// Rewrite the vermagic entry of .modinfo.  Returns the new image length: the
/// replacement is appended, because the expected string can be longer than the
/// one compiled in.
fn patch_vermagic(buf: &mut Vec<u8>, want: &str) -> Option<usize> {
    let secs = Sections::parse(buf)?;
    let idx = (0..secs.num).find(|i| secs.name(buf, *i) == ".modinfo")?;

    let off = secs.offset(buf, idx);
    let size = secs.size(buf, idx);
    let align = rd64(buf, secs.at(idx) + 48).unwrap_or(1).max(1) as usize;

    let mut blob: Vec<u8> = Vec::with_capacity(size + want.len() + 16);
    let mut pos = 0;
    let mut replaced = false;
    while pos < size {
        let start = pos;
        while pos < size && buf[off + pos] != 0 {
            pos += 1;
        }
        let entry = &buf[off + start..off + pos];
        if entry.starts_with(b"vermagic=") {
            blob.extend_from_slice(b"vermagic=");
            blob.extend_from_slice(want.as_bytes());
            blob.push(0);
            replaced = true;
        } else {
            blob.extend_from_slice(entry);
            blob.push(0);
        }
        pos += 1;
    }
    if !replaced {
        return None;
    }
    blob.push(0);

    let noff = (buf.len() + align - 1) & !(align - 1);
    buf.resize(noff + blob.len(), 0);
    buf[noff..noff + blob.len()].copy_from_slice(&blob);
    wr64(buf, secs.at(idx) + 24, noff as u64);
    wr64(buf, secs.at(idx) + 32, blob.len() as u64);
    Some(noff + blob.len())
}

/// What the kernel says it expected after rejecting an insert.
fn wanted_vermagic(lines: &[String]) -> Option<String> {
    for line in lines {
        if let Some(p) = line.find("should be '") {
            let rest = &line[p + 11..];
            if let Some(end) = rest.find('\'') {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

/// Reads /dev/kmsg so the reason for a refusal can be written to lkm.log
/// instead of disappearing into the kernel buffer.
struct Kmsg(Option<fs::File>);

impl Kmsg {
    fn open() -> Self {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open("/dev/kmsg")
            .ok()
            .or_else(|| {
                fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(O_NONBLOCK)
                    .open("/proc/kmsg")
                    .ok()
            });
        let file = file.map(|mut f| {
            let _ = f.seek(SeekFrom::End(0));
            f
        });
        Self(file)
    }

    fn drain(&mut self) -> Vec<String> {
        let Some(file) = self.0.as_mut() else {
            return Vec::new();
        };
        let mut out = String::new();
        let mut chunk = [0u8; 8192];
        loop {
            match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => out.push_str(&String::from_utf8_lossy(&chunk[..n])),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break, // EAGAIN: nothing new
            }
        }
        out.lines().map(str::to_string).collect()
    }
}

const FTRACE_NEED: [(&str, &str); 4] = [
    ("addr_statx", "__arm64_sys_statx"),
    ("addr_newfstatat", "__arm64_sys_newfstatat"),
    ("addr_statfs", "__arm64_sys_statfs"),
    ("addr_fstatfs", "__arm64_sys_fstatfs"),
];

fn ftrace_params(syms: &std::collections::HashMap<String, u64>) -> String {
    let mut out: Vec<String> = Vec::new();
    for (param, name) in FTRACE_NEED {
        if let Some(addr) = syms.get(name) {
            out.push(format!("{param}=0x{addr:x}"));
        }
    }
    out.join(" ")
}

/// The module parameters are the first attempt, but a load through a wrapper
/// that drops the argument string leaves the LKM with zeros.  Write the same
/// addresses next to the module so the mount library can deliver them over the
/// key channel before it starts observing.
fn save_addrs(syms: &std::collections::HashMap<String, u64>) {
    let mut text = String::new();
    for (param, name) in FTRACE_NEED {
        if let Some(addr) = syms.get(name) {
            text.push_str(&format!("{param} 0x{addr:x}\n"));
        }
    }
    if text.lines().count() == 4 {
        let _ = fs::write(module_dir().join("ftrace-addrs"), text);
    }
}

fn init_module_call(buf: &[u8], len: usize, params: &CString) -> c_long {
    unsafe {
        syscall(
            SYS_INIT_MODULE,
            buf.as_ptr() as c_long,
            len as c_long,
            params.as_ptr() as c_long,
        )
    }
}

fn finit_module_call(buf: &[u8], len: usize, params: &CString) -> c_long {
    let name = CString::new("mh").expect("literal");
    let fd = unsafe { syscall(SYS_MEMFD_CREATE, name.as_ptr() as c_long, 1 as c_long) };
    if fd < 0 {
        return -1;
    }
    let fd = fd as i32;
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    if file.write_all(&buf[..len]).is_err() || file.seek(SeekFrom::Start(0)).is_err() {
        return -1;
    }
    unsafe { syscall(SYS_FINIT_MODULE, fd as c_long, params.as_ptr() as c_long, 0 as c_long) }
}

fn modinfo_str(buf: &[u8], key: &str) -> Option<String> {
    let needle = key.as_bytes();
    let pos = buf.windows(needle.len()).position(|w| w == needle)?;
    let rest = &buf[pos + needle.len()..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(0);
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn insert(path: &Path) -> Result<(), String> {
    let syms = kallsyms();
    let params = ftrace_params(&syms);
    let cparams = CString::new(params.clone()).map_err(|e| e.to_string())?;

    let mut image = fs::read(path).map_err(|e| e.to_string())?;
    if image.len() < 64 || &image[..4] != b"\x7fELF" {
        return Err("not an ELF64 module".into());
    }
    if let Some(cfg) = modinfo_str(&image, "mh_ftrace_cfg=") {
        println!("  build cfg: {cfg}");
    }
    let (resolved, undef) = resolve_undef(&mut image, &syms);
    let mut len = image.len();
    // Room for a vermagic replacement appended past the last section.
    image.resize(len + 8192, 0);

    let mut kmsg = Kmsg::open();
    let _ = kmsg.drain();

    let mut last_err = 0i32;
    let mut lines: Vec<String> = Vec::new();
    for _ in 0..5 {
        let rc = init_module_call(&image, len, &cparams);
        if rc == 0 {
            save_addrs(&syms);
            report_params(&params, resolved, undef);
            return Ok(());
        }
        last_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

        // Some kernels refuse init_module from a module-free context but allow
        // the fd based variant, which is also what insmod uses.
        if last_err == 38 || last_err == 1 || last_err == 13 {
            if finit_module_call(&image, len, &cparams) == 0 {
                save_addrs(&syms);
                report_params(&params, resolved, undef);
                return Ok(());
            }
            last_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }

        std::thread::sleep(Duration::from_millis(50));
        lines = kmsg.drain();

        let Some(want) = wanted_vermagic(&lines) else {
            break;
        };
        match patch_vermagic(&mut image, &want) {
            Some(new_len) => {
                println!("  vermagic patch -> {want}");
                len = new_len;
            }
            None => break,
        }
    }

    for line in lines
        .iter()
        .filter(|l| l.contains("magic_hide") || l.contains("module"))
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .iter()
        .rev()
    {
        println!("  kmsg: {line}");
    }
    Err(format!("init_module errno {last_err}"))
}

fn report_params(params: &str, resolved: usize, undef: usize) {
    let n = params.split_whitespace().count();
    println!("  ftrace: {n}/4 syscall addresses passed");
    if undef > 0 {
        println!("  symbols: {resolved}/{undef} undefined resolved from kallsyms");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wr32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put(buf: &mut Vec<u8>, data: &[u8]) -> usize {
        while buf.len() % 8 != 0 {
            buf.push(0);
        }
        let off = buf.len();
        buf.extend_from_slice(data);
        off
    }

    /// Minimal ELF64 relocatable: .shstrtab, .modinfo, .symtab, .strtab and one
    /// undefined symbol named "vmalloc".
    fn image() -> Vec<u8> {
        let shstr = b"\0.shstrtab\0.modinfo\0.symtab\0.strtab\0".to_vec();
        let modinfo = b"license=GPL\0vermagic=5.10.0-test\0\0".to_vec();
        let strtab = b"\0vmalloc\0".to_vec();
        let mut symtab = vec![0u8; 24];
        wr32(&mut symtab, 0, 1); // st_name -> "vmalloc"

        let mut buf = vec![0u8; 64];
        buf[0..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        let shstr_off = put(&mut buf, &shstr);
        let modinfo_off = put(&mut buf, &modinfo);
        let strtab_off = put(&mut buf, &strtab);
        let symtab_off = put(&mut buf, &symtab);

        while buf.len() % 8 != 0 {
            buf.push(0);
        }
        let shoff = buf.len();
        buf.resize(shoff + 5 * 64, 0);
        let sh = |i: usize| shoff + i * 64;
        wr32(&mut buf, sh(1), 1);
        wr32(&mut buf, sh(1) + 4, 3); // STRTAB
        wr64(&mut buf, sh(1) + 24, shstr_off as u64);
        wr64(&mut buf, sh(1) + 32, shstr.len() as u64);
        wr32(&mut buf, sh(2), 11);
        wr32(&mut buf, sh(2) + 4, 1); // PROGBITS
        wr64(&mut buf, sh(2) + 24, modinfo_off as u64);
        wr64(&mut buf, sh(2) + 32, modinfo.len() as u64);
        wr64(&mut buf, sh(2) + 48, 1);
        wr32(&mut buf, sh(3), 20);
        wr32(&mut buf, sh(3) + 4, 2); // SYMTAB
        wr64(&mut buf, sh(3) + 24, symtab_off as u64);
        wr64(&mut buf, sh(3) + 32, 24);
        wr32(&mut buf, sh(3) + 40, 4); // link -> .strtab
        wr64(&mut buf, sh(3) + 56, 24);
        wr32(&mut buf, sh(4), 28);
        wr32(&mut buf, sh(4) + 4, 3);
        wr64(&mut buf, sh(4) + 24, strtab_off as u64);
        wr64(&mut buf, sh(4) + 32, strtab.len() as u64);

        wr64(&mut buf, 0x28, shoff as u64);
        wr16(&mut buf, 0x3a, 64);
        wr16(&mut buf, 0x3c, 5);
        wr16(&mut buf, 0x3e, 1);
        buf
    }

    #[test]
    fn resolves_undefined_symbols_as_absolute() {
        let mut buf = image();
        let mut syms = std::collections::HashMap::new();
        syms.insert("vmalloc".to_string(), 0xdead_beefu64);
        let (resolved, undef) = resolve_undef(&mut buf, &syms);
        assert_eq!((resolved, undef), (1, 1));

        let secs = Sections::parse(&buf).expect("sections");
        let sym_off = secs.offset(&buf, 3);
        assert_eq!(rd64(&buf, sym_off + 8), Some(0xdead_beef));
        assert_eq!(rd16(&buf, sym_off + 6), Some(0xfff1));
    }

    #[test]
    fn rewrites_vermagic_in_place_of_the_module_info() {
        let mut buf = image();
        let len = patch_vermagic(&mut buf, "5.10.0-android12-9-g0123abc").expect("patched");
        assert!(len > 64);

        let secs = Sections::parse(&buf).expect("sections");
        let off = secs.offset(&buf, 2);
        let size = secs.size(&buf, 2);
        let text = String::from_utf8_lossy(&buf[off..off + size]).into_owned();
        assert!(text.contains("vermagic=5.10.0-android12-9-g0123abc"));
        assert!(text.contains("license=GPL"));
        assert_eq!(len, off + size);
    }

    #[test]
    fn resolves_mountinfo_parents_and_escapes() {
        let text = "744 743 253:4 / / rw,relatime shared:1 - ext4 /dev/block/dm-4 rw,seclabel\n\
                    745 744 0:25 / /system ro,relatime - ext4 /dev/block/dm-5 ro,seclabel\n\
                    746 745 0:26 / /system/app/Foo\\040Bar rw - tmpfs workdir rw\n";
        let mounts = parse_mountinfo(text);
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[1].canon, "/system\t/\tro,relatime\text4\t/dev/block/dm-5\tro,seclabel\t/");
        assert_eq!(mounts[2].point, "/system/app/Foo Bar");
        assert_eq!(
            mounts[2].canon,
            "/system/app/Foo Bar\t/\trw\ttmpfs\tworkdir\trw\t/system"
        );
    }

    #[test]
    fn reports_only_the_lines_that_differ() {
        let a = parse_mountinfo("1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / /data rw - ext4 /dev/x rw\n");
        let b = parse_mountinfo("1 0 0:1 / / rw - rootfs rootfs rw\n3 1 0:3 / /system ro - ext4 /dev/y ro\n");
        let (a_only, b_only) = only_in(&a, &b);
        assert_eq!(a_only.len(), 1);
        assert!(a_only[0].starts_with("/data\t"));
        assert_eq!(b_only.len(), 1);
        assert!(b_only[0].starts_with("/system\t"));
    }

    #[test]
    fn collects_only_mountpoints() {
        let text = "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 /foo /x\\040y rw - tmpfs a rw\n";
        let points = mount_points(text);
        assert_eq!(points.len(), 2);
        assert!(points.contains("/"));
        assert!(points.contains("/x y"));
    }
}

// ---------------------------------------------------------------- commands

/// Other kernel modules that rewrite the same views.  Running two at once
/// double-hides, and every diagnosis (a missing font, a leaked mount) becomes
/// ambiguous.  This is reported, never enforced: refusing to load could leave a
/// device without any mount core at all.
const CONFLICTING: &[&str] = &[
    "pathmask",
    "procguard",
    "nomount",
    "susfs_guard_lkm",
    "hybridmount",
    "kasumi",
];

fn conflicts() -> Vec<String> {
    let Ok(text) = fs::read_to_string("/proc/modules") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "magic_hide" && CONFLICTING.contains(name))
        .map(str::to_string)
        .collect()
}

fn report_conflicts() {
    for name in conflicts() {
        println!("magic_hide: conflict: {name} also rewrites mount/stat views");
    }
}

fn load() {
    if loaded() {
        println!("magic_hide: already loaded");
        report_conflicts();
        return;
    }
    if !cfg!(target_arch = "aarch64") {
        println!("magic_hide: unsupported architecture");
        return;
    }

    let list = candidates();
    if list.is_empty() {
        println!("magic_hide: no .ko built for {}", release());
        for dir in scan_dirs() {
            let count = fs::read_dir(&dir)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_name().to_string_lossy().ends_with(".ko"))
                        .count()
                })
                .unwrap_or(0);
            println!("  scanned: {} ({count} .ko)", dir.display());
        }
        if scan_dirs().is_empty() {
            println!("  scanned: no lkm directory exists");
        }
        return;
    }

    for path in list {
        match insert(&path) {
            Ok(()) if loaded() => {
                println!("magic_hide: loaded {}", path.file_name().unwrap_or_default().to_string_lossy());
                report_conflicts();
                return;
            }
            Ok(()) => eprintln!(
                "magic_hide: {}: insmod reported success but the module is absent",
                path.display()
            ),
            Err(err) => eprintln!("magic_hide: {}: {err}", path.display()),
        }
    }
    println!("magic_hide: no compatible .ko for {}", release());
}

/// Run one of the `__` subcommands in a child and kill it at the deadline.
fn supervise(action: &str, arg: &str, deadline: Duration) {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("loader: cannot locate itself: {err}");
            exit(1);
        }
    };

    if action == "__mount" {
        let failures = read_count(&failures_file());
        if failures >= 2 {
            println!(
                "magic_mount: {failures} failed boots in a row, skipping the mount this boot"
            );
            write_count(&failures_file(), 0);
            return;
        }
    }

    let mut child = match Command::new(exe)
        .arg(action)
        .arg(arg)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("loader: cannot start {action}: {err}");
            exit(1);
        }
    };

    let start = Instant::now();
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(1),
            Ok(None) => {}
            Err(err) => {
                eprintln!("loader: waiting for {action} failed: {err}");
                break 1;
            }
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "loader: {action} did not finish in {}s, killed",
                deadline.as_secs()
            );
            cleanup_workdirs();
            break 124;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    if action == "__mount" {
        let failures = read_count(&failures_file());
        if code == 0 {
            write_count(&failures_file(), 0);
        } else if code != EXIT_NO_LIBRARY {
            write_count(&failures_file(), failures + 1);
        }
    }
    exit(code);
}

/// A killed mount pass never reaches its own teardown, and the workspace it
/// mounted would stay visible in mountinfo for the rest of the boot.
fn cleanup_workdirs() {
    for dir in ["/debug_ramdisk/workdir", "/sbin/workdir", "/tmp/workdir"] {
        if Path::new(dir).exists() {
            let _ = Command::new("/system/bin/umount").arg("-l").arg(dir).status();
        }
    }
}

fn run_native(symbol: &str, arg: &str) {
    let path = library();
    let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
        exit(EXIT_NO_LIBRARY);
    };
    let handle = unsafe { dlopen(cpath.as_ptr(), 2 /* RTLD_NOW */) };
    if handle.is_null() {
        eprintln!("loader: cannot load {}", path.display());
        exit(EXIT_NO_LIBRARY);
    }

    let name = CString::new(symbol).expect("symbol");
    let func = unsafe { dlsym(handle, name.as_ptr()) };
    if func.is_null() {
        eprintln!("loader: {symbol} not found in {}", path.display());
        exit(EXIT_NO_LIBRARY);
    }

    let code = if symbol == "refresh_hide_exec" {
        let f: extern "C" fn() -> c_int = unsafe { std::mem::transmute(func) };
        f()
    } else {
        let f: extern "C" fn(*const c_char) -> c_int = unsafe { std::mem::transmute(func) };
        let Ok(source) = CString::new(arg) else { exit(1) };
        f(source.as_ptr())
    };
    exit(if code == 0 { 0 } else { 1 });
}

fn status() {
    let rel = release();
    let (tag, version) = release_info(&rel);
    println!("kernel:   {rel}");
    println!(
        "kmi:      {}",
        match (&tag, &version) {
            (Some(tag), Some(version)) => format!("{tag}-{version}"),
            (None, Some(version)) => format!("unknown-{version}"),
            _ => "unknown".to_string(),
        }
    );
    println!("platform: {}", property("ro.build.version.release"));
    println!("arch:     {}", std::env::consts::ARCH);
    println!("state:    {}", if loaded() { "loaded" } else { "not loaded" });
    let conflicts = conflicts();
    println!(
        "conflict: {}",
        if conflicts.is_empty() { "none".to_string() } else { conflicts.join(", ") }
    );
    println!("dir:      {}", module_dir().display());
    println!("failures: {}", read_count(&failures_file()));
    let records = fs::read_to_string(module_dir().join("hide-records.map"))
        .map(|text| text.lines().filter(|line| !line.is_empty()).count())
        .unwrap_or(0);
    println!("records:  {records}");

    let tried: Vec<String> = candidates()
        .iter()
        .map(|p| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
        .collect();
    println!(
        "try:      {}",
        if tried.is_empty() { "none".to_string() } else { tried.join(" -> ") }
    );

    let mut shipped: Vec<String> = Vec::new();
    for dir in scan_dirs() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for name in entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
            {
                if name.starts_with("magic_hide") && name.ends_with(".ko") && !shipped.contains(&name)
                {
                    shipped.push(name);
                }
            }
        }
    }
    shipped.sort();
    println!("shipped:  {}", if shipped.is_empty() { "none".to_string() } else { shipped.join(" ") });
    for dir in scan_dirs() {
        println!("scan:     {}", dir.display());
    }

    let stats = fs::read_to_string(stats_file()).unwrap_or_default();
    match stats.lines().next() {
        Some(first) => println!("stats:    {first}"),
        None => println!("stats:    none"),
    }
}

// ------------------------------------------------------- donor namespace
//
// Kasumi answers "what would mountinfo look like without us?" by swapping the
// reader's namespace pointer inside the kernel.  We cannot use an unexported
// `struct mnt_namespace` portably, and swapping it would also freeze the view
// at mount time, so the same question is answered out here instead: clone the
// mount namespace, drop the propagation link that would let an unmount escape,
// detach every mountpoint we published, and read the result.  That donor view
// is then compared with the view this process has, which is the one magic_hide
// filtered.

const CLONE_NEWNS: c_int = 0x0002_0000;
const MS_REC: c_ulong = 1 << 14;
const MS_PRIVATE: c_ulong = 1 << 18;
const MNT_DETACH: c_int = 2;

extern "C" {
    fn unshare(flags: c_int) -> c_int;
    fn mount(
        source: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    fn umount2(target: *const c_char, flags: c_int) -> c_int;
    fn statfs(path: *const c_char, buf: *mut StatfsBuf) -> c_int;
    fn getuid() -> u32;
}

/// One mountinfo line reduced to what survives a namespace copy.  Mount ids
/// are allocated per namespace, so the parent id is resolved to its mountpoint
/// and both numbers are dropped; the `shared:`/`master:` tags are dropped too,
/// because the donor namespace is made private before anything is unmounted.
struct MiMount {
    point: String,
    canon: String,
}

/// mountinfo escapes space, tab, newline and backslash (`\040`, `\011`,
/// `\012`, `\134`); the record list holds the raw path.
fn unescape(field: &str) -> String {
    let src = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\'
            && i + 3 < src.len()
            && src[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b))
        {
            let v = ((src[i + 1] - b'0') as u32) << 6
                | ((src[i + 2] - b'0') as u32) << 3
                | (src[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(src[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_mountinfo(text: &str) -> Vec<MiMount> {
    // id, parent id, root, mount point, mount options, fstype, source, super options
    let mut raw: Vec<(u64, u64, String, String, String, String, String, String)> = Vec::new();
    for line in text.lines() {
        let Some(split) = line.find(" - ") else { continue };
        let left: Vec<&str> = line[..split].split_whitespace().collect();
        let right: Vec<&str> = line[split + 3..].split_whitespace().collect();
        if left.len() < 6 || right.len() < 3 {
            continue;
        }
        let (Ok(id), Ok(parent)) = (left[0].parse::<u64>(), left[1].parse::<u64>()) else {
            continue;
        };
        raw.push((
            id,
            parent,
            unescape(left[3]),
            unescape(left[4]),
            left[5].to_string(),
            right[0].to_string(),
            unescape(right[1]),
            right[2].to_string(),
        ));
    }

    let points: BTreeMap<u64, String> = raw.iter().map(|r| (r.0, r.3.clone())).collect();
    raw.into_iter()
        .map(|(_, parent, root, point, opts, fstype, source, superopts)| {
            let parent_point = points.get(&parent).cloned().unwrap_or_default();
            let canon = format!("{point}\t{root}\t{opts}\t{fstype}\t{source}\t{superopts}\t{parent_point}");
            MiMount { point, canon }
        })
        .collect()
}

/// Lines present in `a` but not `b`, and the other way round.
fn only_in(a: &[MiMount], b: &[MiMount]) -> (Vec<String>, Vec<String>) {
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for m in a {
        *counts.entry(m.canon.as_str()).or_default() += 1;
    }
    for m in b {
        *counts.entry(m.canon.as_str()).or_default() -= 1;
    }
    let (mut a_only, mut b_only) = (Vec::new(), Vec::new());
    for (canon, n) in counts {
        for _ in 0..n.max(0) {
            a_only.push(canon.to_string());
        }
        for _ in 0..(-n).max(0) {
            b_only.push(canon.to_string());
        }
    }
    (a_only, b_only)
}

/// Every mountpoint in a mountinfo snapshot.  The donor child only needs this
/// set, so it skips the parent/id work the full parser does.
fn mount_points(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|line| {
            let split = line.find(" - ")?;
            let left: Vec<&str> = line[..split].split_whitespace().collect();
            if left.len() < 5 {
                return None;
            }
            Some(unescape(left[4]))
        })
        .collect()
}

/// The child half: enter a private copy of the mount namespace, detach every
/// published mountpoint, then print what is left.  The work happens after
/// `exec`, so no allocation runs between fork and exec, and only paths that
/// really are mountpoints here cost a syscall.
fn donor_view() {
    let Some(map) = std::env::args().nth(2) else {
        eprintln!("donor-view: missing record list");
        exit(2);
    };
    let text = match fs::read_to_string(&map) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("donor-view: cannot read {map}: {err}");
            exit(2);
        }
    };
    let mut records: Vec<String> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    // Deepest first: a bind mount lives on the tmpfs skeleton above it, so it
    // has to be detached before that skeleton goes away.
    records.sort_by_key(|path| std::cmp::Reverse(path.len()));

    let root = CString::new("/").expect("literal");
    if unsafe { unshare(CLONE_NEWNS) } != 0 {
        eprintln!("donor-view: unshare: {}", std::io::Error::last_os_error());
        exit(2);
    }
    // Must happen before the first umount: the copy still shares propagation
    // with the parent namespace, and a shared unmount would remove our mounts
    // from the running system.
    let rc = unsafe {
        mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            MS_REC | MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        eprintln!(
            "donor-view: private propagation: {}",
            std::io::Error::last_os_error()
        );
        exit(2);
    }

    let before = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let points = mount_points(&before);
    for path in &records {
        if !points.contains(path) {
            continue; // stale record, not a mountpoint any more
        }
        let Ok(cpath) = CString::new(path.as_str()) else {
            continue;
        };
        unsafe { umount2(cpath.as_ptr(), MNT_DETACH) };
    }

    // Re-read instead of filtering the first snapshot: detaching our mount can
    // reveal a stock mount that was covered at the same path.
    let after = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mut out = std::io::stdout();
    let _ = out.write_all(after.as_bytes());
    let _ = out.flush();
    exit(0);
}

fn donor_check() {
    let map = module_dir().join("hide-records.map");
    let text = match fs::read_to_string(&map) {
        Ok(text) => text,
        Err(err) => {
            println!("donor-check: cannot read {}: {err}", map.display());
            exit(2);
        }
    };
    let records: Vec<String> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if records.is_empty() {
        println!("donor-check: {} is empty, nothing published yet", map.display());
        exit(2);
    }

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            println!("donor-check: cannot locate itself: {err}");
            exit(2);
        }
    };
    let mut cmd = Command::new(exe);
    cmd.arg("__donor-view")
        .arg(&map)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let started = Instant::now();
    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => {
            println!("donor-check: cannot build a donor namespace: {err}");
            exit(2);
        }
    };
    let namespace_us = started.elapsed().as_micros();
    if !output.status.success() {
        println!("donor-check: donor reader failed: {}", output.status);
        exit(2);
    }

    let donor = parse_mountinfo(&String::from_utf8_lossy(&output.stdout));
    let compare_started = Instant::now();
    let live_all = parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").unwrap_or_default());

    // A record path is by definition covered, so a line for it means the
    // kernel did not hide it from this reader (APPS mode exempts uid 0, or the
    // .ko is not loaded).  Drop exactly those lines and report the count; any
    // other leaked mount, such as a workspace tmpfs, still shows up as a diff.
    let record_set: HashSet<&str> = records.iter().map(String::as_str).collect();
    let donor_points: HashSet<&str> = donor.iter().map(|m| m.point.as_str()).collect();
    let mut visible = 0usize;
    let live: Vec<MiMount> = live_all
        .into_iter()
        .filter(|m| {
            if record_set.contains(m.point.as_str()) && !donor_points.contains(m.point.as_str()) {
                visible += 1;
                false
            } else {
                true
            }
        })
        .collect();

    let (only_donor, only_live) = only_in(&donor, &live);
    let diff = only_donor.len() + only_live.len();
    let compare_us = compare_started.elapsed().as_micros();
    println!(
        "donor-check: donor={} live={} diff={diff} covered-visible={visible}",
        donor.len(),
        live.len()
    );
    println!("  cost: donor_ns={namespace_us}us compare={compare_us}us");
    if visible > 0 {
        println!(
            "  hint: {visible} covered mountpoint(s) are still listed for uid {} (APPS mode exempts root, or magic_hide is not filtering)",
            unsafe { getuid() }
        );
    }
    for line in only_donor.iter().take(8) {
        println!("  only in donor: {}", line.replace('\t', " "));
    }
    if only_donor.len() > 8 {
        println!("  ... {} more only in donor", only_donor.len() - 8);
    }
    for line in only_live.iter().take(8) {
        println!("  only in live:  {}", line.replace('\t', " "));
    }
    if only_live.len() > 8 {
        println!("  ... {} more only in live", only_live.len() - 8);
    }

    exit(if diff == 0 { 0 } else { 1 });
}

// ------------------------------------------------------- overhead probe

const BENCH_ITER: usize = 2000;

/// Opaque storage for `struct statfs`; every Android ABI keeps it well under
/// 256 bytes and only the return value is used here.
#[repr(C)]
struct StatfsBuf {
    raw: [u64; 32],
}

fn stat_cost(path: &Path, iterations: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = fs::metadata(path);
    }
    start.elapsed().as_nanos() / iterations.max(1) as u128
}

fn statfs_cost(path: &Path, iterations: usize) -> Option<u128> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = StatfsBuf { raw: [0; 32] };
    let start = Instant::now();
    for _ in 0..iterations {
        if unsafe { statfs(cpath.as_ptr(), &mut buf) } != 0 {
            return None;
        }
    }
    Some(start.elapsed().as_nanos() / iterations.max(1) as u128)
}

/// Per-call cost of the two syscalls magic_hide intercepts, on a path it covers
/// and on an ordinary one.  Both sides pay the kretprobe trampoline, so the
/// difference is what the hot lookup and the forged answer add - that is the
/// number to watch across builds.  Informational: latencies are noisy and no
/// threshold is enforced.
fn bench() {
    let iterations = std::env::args()
        .nth(2)
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(BENCH_ITER)
        .clamp(100, 100_000);

    let map = module_dir().join("hide-records.map");
    let records = fs::read_to_string(&map).unwrap_or_default();
    let Some(covered) = records
        .lines()
        .find(|line| !line.is_empty() && Path::new(line).exists())
        .map(Path::new)
    else {
        println!("bench: no published mountpoint exists yet (run the mount stage first)");
        exit(2);
    };
    let native = ["/data/local/tmp", "/data"]
        .iter()
        .map(Path::new)
        .find(|path| path.is_dir())
        .unwrap_or_else(|| Path::new("/"));

    println!(
        "bench: iter={iterations} covered={} native={}",
        covered.display(),
        native.display()
    );

    let c = stat_cost(covered, iterations);
    let n = stat_cost(native, iterations);
    println!(
        "bench: stat covered_ns={c} native_ns={n} delta_ns={}",
        c as i128 - n as i128
    );

    match (
        statfs_cost(covered, iterations),
        statfs_cost(native, iterations),
    ) {
        (Some(c), Some(n)) => println!(
            "bench: statfs covered_ns={c} native_ns={n} delta_ns={}",
            c as i128 - n as i128
        ),
        _ => println!("bench: statfs unavailable on this path"),
    }

    let mut lines = 0;
    let start = Instant::now();
    for _ in 0..20 {
        lines = fs::read_to_string("/proc/self/mountinfo")
            .map(|text| text.lines().count())
            .unwrap_or(0);
    }
    println!(
        "bench: mountinfo lines={lines} read_us={}",
        start.elapsed().as_micros() / 20
    );
    exit(0);
}

fn unload() {
    if !loaded() {
        println!("magic_hide: not loaded");
        return;
    }
    let name = CString::new("magic_hide").expect("name");
    let rc = unsafe { syscall(SYS_DELETE_MODULE, name.as_ptr() as c_long, O_NONBLOCK as c_long) };
    if rc == 0 {
        println!("magic_hide: unloaded");
    } else {
        eprintln!("magic_hide: unload failed: {}", std::io::Error::last_os_error());
    }
}
