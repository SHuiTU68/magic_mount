use mlua_sys::lua54::lua::*;
use std::os::raw::c_int;
use log::LevelFilter;
use android_logger::Config;
mod magic_mount;
mod defs;
mod hide;
mod moddir;
mod parallel;
mod restorecon;
mod stats;
mod utils;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn _init() {}

unsafe extern "C-unwind" fn magic_mount(state: *mut lua_State) -> c_int { unsafe {
    //println!("Hello from Rust!");

    unsafe {
        let mount_source_cstr = lua_tolstring(state, 1, std::ptr::null_mut());
        
        if mount_source_cstr.is_null() {
            lua_pushstring(state, b"Error: missing or invalid mount_source parameter\0".as_ptr() as *const _);
            lua_error(state);
            return 0;
        }
        
        let mount_source = std::ffi::CStr::from_ptr(mount_source_cstr)
            .to_str()
            .unwrap_or("unknown");
        
        println!("Received mount_source from Lua: {}", mount_source);
        

        let _ = magic_mount::magic_mount(mount_source);
        
        lua_pushstring(state, b"Hello from Rust!\0".as_ptr() as *const _);
        1
    }

    
}}
/// Tell the library where this module lives.
///
/// A metamodule is not under /data/adb/modules/<id> (APatch uses
/// /data/adb/metamodule), so the state files would otherwise land in a
/// directory that does not exist.  The Lua host passes MODDIR once per stage.
unsafe extern "C-unwind" fn configure_dir(state: *mut lua_State) -> c_int { unsafe {
    let dir = lua_tolstring(state, 1, std::ptr::null_mut());
    if !dir.is_null() {
        if let Ok(dir) = std::ffi::CStr::from_ptr(dir).to_str() {
            moddir::set(dir);
        }
    }
    0
}}

/// Rebind the already published hiding records to the current mounts.
///
/// Called from the late-start service stage: a mount created after the first
/// publish has a new root dentry, and the LKM's lookup is keyed on it.
unsafe extern "C-unwind" fn refresh_hide(state: *mut lua_State) -> c_int { unsafe {
    let ok = hide::refresh();
    lua_pushboolean(state, if ok { 1 } else { 0 });
    1
}}

/// Start or stop the LKM's caller observer and return what it collected.
///
/// The observer is the ftrace probe on the stat syscalls, so the LKM knows
/// which uids query the mount table without a kprobe on the hot path.
unsafe extern "C-unwind" fn observe_hide(state: *mut lua_State) -> c_int { unsafe {
    let on = lua_toboolean(state, 1) != 0;
    let events = hide::observe(on);

    lua_newtable(state);
    for (i, ev) in events.iter().enumerate() {
        lua_newtable(state);
        lua_pushinteger(state, ev.uid as _);
        lua_setfield(state, -2, b"uid\0".as_ptr() as _);
        lua_pushinteger(state, ev.pid as _);
        lua_setfield(state, -2, b"pid\0".as_ptr() as _);
        lua_pushinteger(state, ev.count as _);
        lua_setfield(state, -2, b"count\0".as_ptr() as _);
        lua_pushstring(state, ev.op_name().as_ptr() as _);
        lua_setfield(state, -2, b"op\0".as_ptr() as _);
        let comm = ev.comm();
        lua_pushlstring(state, comm.as_ptr() as _, comm.len());
        lua_setfield(state, -2, b"comm\0".as_ptr() as _);
        lua_rawseti(state, -2, (i + 1) as _);
    }
    1
}}

/// Apply `hide-exempt-uids`, drain the hit and observer tables, then write
/// `hide-hits.log`, `hide-exempt-uids.suggested` and `hide-events.log`.  Called
/// at boot_completed.
unsafe extern "C-unwind" fn report_hide(state: *mut lua_State) -> c_int { unsafe {
    let ok = hide::report();
    lua_pushboolean(state, if ok { 1 } else { 0 });
    1
}}

/// Plain C entry points used by lkm/loader.
///
/// The loader runs the mount pass in a child process so that a panic, a
/// deadlock or a crash costs one boot instead of looping forever; it dlopens
/// this library and calls these two symbols.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn magic_mount_exec(source: *const std::os::raw::c_char) -> c_int {
    if source.is_null() {
        return -1;
    }
    let Ok(source) = (unsafe { std::ffi::CStr::from_ptr(source) }).to_str() else {
        return -1;
    };
    match magic_mount::magic_mount(source) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("magic_mount: {err:#}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn refresh_hide_exec() -> c_int {
    if hide::refresh() { 0 } else { -1 }
}

// --------------------------
// Lua require("libmagic_mount") 时执行的入口
// --------------------------


#[unsafe(no_mangle)]
pub unsafe extern "C" fn luaopen_libmagic_mount(state: *mut lua_State) -> c_int { unsafe {
    
    static INIT: std::sync::Once = std::sync::Once::new();

    INIT.call_once(|| {
        android_logger::init_once(
            Config::default()
                .with_tag("Magiskmount")
                // Per-file debug logging dominated the mount time on modules
                // with thousands of entries; debug lines are now compiled
                // away by the level check.
                .with_max_level(LevelFilter::Info),
        );
        log::info!("logger initialized");
    });
    
    lua_newtable(state);

    lua_pushcfunction(state, configure_dir);
    lua_setfield(state, -2, b"configure\0".as_ptr() as _);

    lua_pushcfunction(state, magic_mount);
    lua_setfield(state, -2, b"magic_mount\0".as_ptr() as _);

    lua_pushcfunction(state, refresh_hide);
    lua_setfield(state, -2, b"refresh_hide\0".as_ptr() as _);

    lua_pushcfunction(state, observe_hide);
    lua_setfield(state, -2, b"observe_hide\0".as_ptr() as _);

    lua_pushcfunction(state, report_hide);
    lua_setfield(state, -2, b"report_hide\0".as_ptr() as _);
    1
}}