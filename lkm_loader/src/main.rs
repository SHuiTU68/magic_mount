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
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};
use std::time::{Duration, Instant};

const SYS_FINIT_MODULE: c_long = 273; // generic arm64 syscall table
const SYS_DELETE_MODULE: c_long = 106;
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

fn insert(path: &Path) -> Result<(), String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let empty = CString::new("").expect("empty");
    let rc = unsafe {
        syscall(
            SYS_FINIT_MODULE,
            file.as_raw_fd() as c_long,
            empty.as_ptr() as c_long,
            0 as c_long,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let errno = std::io::Error::last_os_error();
    // Old or hardened kernels are not always happy with finit_module; the
    // stock insmod binary does the same open+init dance with its own checks.
    for insmod in ["/system/bin/insmod", "/vendor/bin/insmod", "insmod"] {
        let out = Command::new(insmod).arg(path).output();
        if let Ok(out) = out {
            if out.status.success() {
                return Ok(());
            }
        }
    }
    Err(errno.to_string())
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
    println!("kernel:   {}", release());
    println!("arch:     {}", std::env::consts::ARCH);
    println!("state:    {}", if loaded() { "loaded" } else { "not loaded" });
    println!("failures: {}", read_count(&failures_file()));

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
