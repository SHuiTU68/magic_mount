
local M = {}



function M.version() --module version(recommended addition)
return 1
end

-- Load the magic_hide LKM before magic_mount starts publishing records.
-- lkm.sh detects the device KMI out of the shipped lkm/ directory and is a
-- no-op when nothing matches or the module is already loaded; a failure only
-- loses the extra hiding, never the mounts.
local function load_lkm()
    local dir = rawget(_G, "MODDIR") or "/data/adb/modules/magic_mount"
    if os.execute then
        os.execute("sh '" .. dir .. "/lkm.sh'")
    end
end

function M.post_fs_data(superkey)
    info("post_fs_data called")
    load_lkm()
end

function M.post_mount(superkey)
    info("post_mount called")
    -- Safety net for root managers that skip post_fs_data; lkm.sh exits
    -- immediately when the module is already loaded.
    load_lkm()
    if superkey=="kernelsu" then
        mount_source= "KSU"
    else
        mount_source= "APatch"
    end
    local libmagisk_mount = require("libmagic_mount")
    libmagisk_mount.magic_mount(mount_source)

end
function M.service(superkey)
    info("service called")
end

function M.action()
    info("action called")
    print("this is action function")
    os.execute("sleep 2")
end
return M
