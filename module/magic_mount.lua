-- magic_mount metamodule lifecycle.
--
-- The root manager calls one stage per boot, in this order:
--
--   post_fs_data   before any module is mounted      -> load the LKM
--   post_mount     after the module trees are up     -> publish + mount
--   service        late_start, every mount has landed-> rebind records
--   boot_completed after the boot finished           -> final rebind
--   action         user tapped the module in the app -> report
--
-- Every stage must survive on its own: the root manager runs metamodules in a
-- chain, and an error thrown here would abort the stages of the modules after
-- us.  Anything that can fail (require of the native library, the mount pass,
-- the LKM loader) is therefore wrapped, and a failure only costs the hiding,
-- never the mount.

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

local function run(cmd)
    if type(os.execute) ~= "function" then
        return false
    end
    local ok, how, code = os.execute(cmd)
    if ok == true or ok == 0 then
        return true
    end
    return how == "exit" and code == 0
end

-- lkm.sh matches the shipped .ko against this device's KMI and exits quietly
-- when nothing matches, so "load" is always safe to call (also twice).
local function lkm(action)
    return run(("sh '%s/lkm.sh' %s"):format(moddir(), action or "load"))
end

local function library()
    local ok, lib = pcall(require, "libmagic_mount")
    if ok and type(lib) == "table" then
        return lib
    end
    log("libmagic_mount unavailable: " .. tostring(lib))
    return nil
end

-- The kernel keys its hiding records on the root dentry of each covered
-- mount, so a mount created after post_mount has a different one.  Rebinding
-- keeps the identity sampled before the first mount and is idempotent, which
-- is why every later stage can call it.
local function rebind()
    local lib = library()
    if lib and type(lib.refresh_hide) == "function" then
        pcall(lib.refresh_hide)
    end
end

local function report()
    local dir = moddir()
    print("magic_mount: " .. (run("test -d /sys/module/magic_hide") and
        "magic_hide loaded" or "magic_hide NOT loaded (mounts are not hidden)"))
    run(("sh '%s/lkm.sh' status"):format(dir))
    print("--- mount timings ---")
    run(("cat '%s/mount-stats.txt' 2>/dev/null"):format(dir))
end

function M.version()
    return 3
end

function M.post_fs_data(superkey)
    log("post_fs_data called")
    lkm("load")
end

function M.post_mount(superkey)
    log("post_mount called")
    -- Safety net for root managers that skip post_fs_data; lkm.sh exits
    -- immediately when the module is already loaded.
    lkm("load")

    local lib = library()
    if not lib or type(lib.magic_mount) ~= "function" then
        return
    end
    local source = (superkey == "kernelsu") and "KSU" or "APatch"
    local ok, err = pcall(lib.magic_mount, source)
    if not ok then
        log("mount failed: " .. tostring(err))
    end
end

function M.service(superkey)
    log("service called")
    rebind()
end

function M.boot_completed(superkey)
    log("boot_completed called")
    rebind()
end

function M.action()
    report()
end

return M
