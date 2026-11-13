//! Loader and mount supervisor shipped as `lkm/loader`.
//!
//! It does the two things a shell script cannot do safely:
//!
//! * `load` matches this device's KMI against the `.ko` files next to the
//!   binary and inserts the first one the kernel accepts.
//! * `mount` / `refresh` run the native mount pass in a child process with a
//!   deadline, so a panic, a crash or a deadlock costs one boot instead of
//!   looping forever.  Two failed boots in a row make the next one skip the
//!   mount entirely, which is what breaks a boot loop: the device comes up
//!   and the boot after that tries again.
//!
//! The layout is `<module>/lkm/loader`, so the module directory and the .ko
//! directory are both derived from the running executable - nothing here
//! hardcodes /data/adb/modules/magic_mount.

use std::ffi::CString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::FromRawFd;
use std::os::raw::{c_char, c_int, c_long, c_void};
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

    match action {
        "load" => load(),
        "mount" => supervise("__mount", args.get(2).map(String::as_str).unwrap_or("APatch"), MOUNT_DEADLINE),
        "refresh" => supervise("__refresh", "", REFRESH_DEADLINE),
        "status" => status(),
        "unload" => unload(),
        "__mount" => run_native("magic_mount_exec", args.get(2).map(String::as_str).unwrap_or("APatch")),
        "__refresh" => run_native("refresh_hide_exec", ""),
        other => {
            eprintln!("usage: loader [load|mount <source>|refresh|status|unload] (got {other})");
            exit(64);
        }
    }
}

// ---------------------------------------------------------------- paths

fn lkm_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("/data/adb/modules/magic_mount/lkm"))
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

    let dir = lkm_dir();
    let shipped: Vec<String> = fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with("magic_hide") && n.ends_with(".ko"))
                .collect()
        })
        .unwrap_or_default();

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
        let path = dir.join(format!("magic_hide-{name}.ko"));
        let path = if path.exists() { path } else { dir.join(format!("{name}.ko")) };
        if path.exists() && !out.contains(&path) {
            out.push(path);
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

fn ftrace_params(syms: &std::collections::HashMap<String, u64>) -> String {
    const NEED: [(&str, &str); 4] = [
        ("addr_statx", "__arm64_sys_statx"),
        ("addr_newfstatat", "__arm64_sys_newfstatat"),
        ("addr_statfs", "__arm64_sys_statfs"),
        ("addr_fstatfs", "__arm64_sys_fstatfs"),
    ];
    let mut out: Vec<String> = Vec::new();
    for (param, name) in NEED {
        if let Some(addr) = syms.get(name) {
            out.push(format!("{param}=0x{addr:x}"));
        }
    }
    out.join(" ")
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

fn insert(path: &Path) -> Result<(), String> {
    let syms = kallsyms();
    let params = ftrace_params(&syms);
    let cparams = CString::new(params.clone()).map_err(|e| e.to_string())?;

    let mut image = fs::read(path).map_err(|e| e.to_string())?;
    if image.len() < 64 || &image[..4] != b"\x7fELF" {
        return Err("not an ELF64 module".into());
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
            report_params(&params, resolved, undef);
            return Ok(());
        }
        last_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

        // Some kernels refuse init_module from a module-free context but allow
        // the fd based variant, which is also what insmod uses.
        if last_err == 38 || last_err == 1 || last_err == 13 {
            if finit_module_call(&image, len, &cparams) == 0 {
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
    fn reads_the_expected_vermagic_from_kmsg() {
        let lines = vec![
            "6,300,1,-;magic_hide: version magic '5.10.0-test' should be '5.10.0-android12-9'".into(),
        ];
        assert_eq!(
            wanted_vermagic(&lines).as_deref(),
            Some("5.10.0-android12-9")
        );
    }
}

// ---------------------------------------------------------------- commands

fn load() {
    if loaded() {
        println!("magic_hide: already loaded");
        return;
    }
    if !cfg!(target_arch = "aarch64") {
        println!("magic_hide: unsupported architecture");
        return;
    }

    let list = candidates();
    if list.is_empty() {
        println!("magic_hide: no .ko built for {}", release());
        return;
    }

    for path in list {
        match insert(&path) {
            Ok(()) if loaded() => {
                println!("magic_hide: loaded {}", path.file_name().unwrap_or_default().to_string_lossy());
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
    println!("dir:      {}", module_dir().display());
    println!("failures: {}", read_count(&failures_file()));

    let tried: Vec<String> = candidates()
        .iter()
        .map(|p| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
        .collect();
    println!(
        "try:      {}",
        if tried.is_empty() { "none".to_string() } else { tried.join(" -> ") }
    );

    let mut shipped: Vec<String> = fs::read_dir(lkm_dir())
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with("magic_hide") && n.ends_with(".ko"))
                .collect()
        })
        .unwrap_or_default();
    shipped.sort();
    println!("shipped:  {}", if shipped.is_empty() { "none".to_string() } else { shipped.join(" ") });

    let stats = fs::read_to_string(stats_file()).unwrap_or_default();
    match stats.lines().next() {
        Some(first) => println!("stats:    {first}"),
        None => println!("stats:    none"),
    }
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
