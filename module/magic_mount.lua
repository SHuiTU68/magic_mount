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

-- 126/127 come from the shell when the file is absent or not executable, which
-- is the only case where the Lua fallback should take over.
local function loader(action)
    local code = run(("'%s/lkm/loader' %s"):format(moddir(), action))
    if code == 126 or code == 127 then
        return nil
    end
    return code
end

local function library()
    local ok, lib = pcall(require, "libmagic_mount")
    if ok and type(lib) == "table" then
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

function M.version()
    return 4
end

function M.post_fs_data(superkey)
    log("post_fs_data called")
    loader("load")
end

function M.post_mount(superkey)
    log("post_mount called")
    -- Safety net for root managers that skip post_fs_data; the loader exits
    -- immediately when the module is already loaded.
    loader("load")

    local source = (superkey == "kernelsu") and "KSU" or "APatch"
    local code = loader("mount " .. source)
    if code == nil or code == 2 then
        fallback_mount(source)
    end
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
end

function M.action()
    if loader("status") == nil then
        -- Older package without lkm/loader: report what we can from the shell.
        run(("cat '%s/mount-stats.txt' 2>/dev/null"):format(moddir()))
    end
end

return M
