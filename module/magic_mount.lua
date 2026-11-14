-- magic_mount metamodule lifecycle.
--
-- The root manager calls one stage per boot, in this order:
--
--   post_fs_data   before any module is mounted      -> load the LKM
--   post_mount     after the module trees are up     -> mount, in a child
--   service        late_start, every mount has landed-> rebind records
--   boot_completed after the boot finished           -> final rebind
--   action         user tapped the module in the app -> report
--
-- Every stage must survive on its own: the root manager runs metamodules in a
-- chain, and an error thrown here would abort the stages of the modules after
-- us.  The heavy lifting lives in lkm/loader, which runs the mount pass in a
-- child process with a deadline; if that binary is missing or cannot load the
-- native library (exit code 2) the old in-process path is used instead.

local M = {}

local MODULE_ID = "magic_mount"
local DEFAULT_DIR = "/data/adb/modules/" .. MODULE_ID

local function moddir()
    local dir = rawget(_G, "MODDIR")
    if type(dir) == "string" and dir ~= "" then
        return dir
    end
    return DEFAULT_DIR
end

local function log(msg)
    if type(info) == "function" then
        info(msg)
    else
        print(msg)
    end
end

-- Exit code of a command, or nil when it could not be run at all.
local function run(cmd)
    if type(os.execute) ~= "function" then
        return nil
    end
    local ok, how, code = os.execute(cmd)
    if ok == true or ok == 0 then
        return 0
    end
    if how == "exit" then
        return code or 1
    end
    return nil
end

-- The package is built from the repository and shipped as a zip: the exec bit
-- on lkm/loader does not survive every download path, and some devices mount
-- /data noexec.  A ROM that installs the metamodule under /data/adb/metamodule
-- also keeps a second copy under /data/adb/modules, and only one of the two is
-- guaranteed to be complete, so both are candidates.
local OTHER_ROOT = "/data/adb/metamodule"

local function roots()
    local out = { moddir() }
    if OTHER_ROOT ~= moddir() then
        out[#out + 1] = OTHER_ROOT
    end
    return out
end

local function first_loader()
    for _, dir in ipairs(roots()) do
        local bin = dir .. "/lkm/loader"
        if run(("test -f '%s'"):format(bin)) == 0 then
            return bin, dir .. "/lkm"
        end
    end
    return nil
end

local function loader(action, log_file)
    local bin, lkdir = first_loader()
    if not bin then
        return nil
    end
    -- Note that a failed command still returns a number: 1 is true in Lua, so
    -- every check here compares against 0 explicitly.
    if run(("test -x '%s'"):format(bin)) ~= 0 then
        run(("chmod 0755 '%s' 2>/dev/null"):format(bin))
    end

    local redirect = ""
    if log_file then
        -- Append: post_fs_data and post_mount both report, and the failure of
        -- the first attempt is the interesting one.
        redirect = (" >>'%s' 2>&1"):format(log_file)
    end
    local env = ("MM_LKM_DIR='%s' MM_MODDIR='%s' "):format(lkdir, moddir())
    local code = run(("%s'%s' %s%s"):format(env, bin, action, redirect))

    -- 127 is what sh returns when it cannot exec the file at all; 126 is a
    -- file that exists but may not be executed.  Both are fixed the same way.
    if code == 126 or code == 127 or code == nil then
        local tmp = "/dev/.mm_loader"
        if run(("cp -f '%s' %s 2>/dev/null && chmod 0755 %s"):format(bin, tmp, tmp)) == 0 then
            code = run(("%s'%s' %s%s"):format(env, tmp, action, redirect))
        end
    end
    if code == 126 or code == 127 or code == nil then
        return nil
    end
    return code
end

local function library()
    local ok, lib = pcall(require, "libmagic_mount")
    if ok and type(lib) == "table" then
        -- A metamodule does not live under /data/adb/modules/<id>; the state
        -- files have to follow MODDIR.
        if type(lib.configure) == "function" then
            pcall(lib.configure, moddir())
        end
        return lib
    end
    log("libmagic_mount unavailable: " .. tostring(lib))
    return nil
end

-- 2: the loader ran but could not dlopen the library.
local function fallback_mount(source)
    local lib = library()
    if lib and type(lib.magic_mount) == "function" then
        local ok, err = pcall(lib.magic_mount, source)
        if not ok then
            log("mount failed: " .. tostring(err))
        end
    end
end

local function fallback_refresh()
    local lib = library()
    if lib and type(lib.refresh_hide) == "function" then
        pcall(lib.refresh_hide)
    end
end

-- Caller observation is driven by the LKM's kprobe entry probes on the stat
-- syscalls.  Turning it on costs one atomic read per stat; the table is
-- drained once at boot_completed and written to hide-events.log.  Separately,
-- every positive hot lookup is counted into a hit table (hide-hits.log).
local function observe(on)
    local lib = library()
    if lib and type(lib.observe_hide) == "function" then
        pcall(lib.observe_hide, on)
    end
end

local function report()
    local lib = library()
    if lib and type(lib.report_hide) == "function" then
        pcall(lib.report_hide)
    end
end

function M.version()
    return 9
end

function M.post_fs_data(superkey)
    log("post_fs_data called")
    loader("load", moddir() .. "/lkm.log")
end

function M.post_mount(superkey)
    log("post_mount called")
    -- Safety net for root managers that skip post_fs_data; the loader exits
    -- immediately when the module is already loaded.
    loader("load", moddir() .. "/lkm.log")

    local source = (superkey == "kernelsu") and "KSU" or "APatch"
    local code = loader("mount " .. source)
    if code == nil or code == 2 then
        fallback_mount(source)
    end
    -- From here on, record who queries the result; boot_completed drains it.
    observe(true)
end

function M.service(superkey)
    log("service called")
    local code = loader("refresh")
    if code == nil or code == 2 then
        fallback_refresh()
    end
end

function M.boot_completed(superkey)
    log("boot_completed called")
    local code = loader("refresh")
    if code == nil or code == 2 then
        fallback_refresh()
    end
    -- Everything that inspects the mount table has run by now: close the
    -- observer, drain the hit table, apply hide-exempt-uids and keep the
    -- summary plus the exemption suggestion draft.
    report()
end

function M.action()
    if loader("status") == nil then
        -- Older package without lkm/loader: report what we can from the shell.
        run(("cat '%s/mount-stats.txt' 2>/dev/null"):format(moddir()))
    end
    -- Re-drain the hit table so an app that was used after boot (the reason a
    -- user taps the module) shows up in hide-hits.log without a reboot.
    report()
end

return M
