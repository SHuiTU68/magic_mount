#!/system/bin/sh
#
# mm_verify.sh -- one-shot self check for magic_mount + magic_hide.
#
# Run as root on the device:
#
#   sh /path/to/mm_verify.sh             # run every check
#   sh /path/to/mm_verify.sh --snapshot  # save a baseline; do this with the
#                                        # module disabled, before reboot
#   sh /path/to/mm_verify.sh --diff      # baseline comparison only
#
# Exit status: 0 all checks passed, 1 at least one check failed, 2 usage.
#
# The write checks open a target O_WRONLY without truncation and write zero
# bytes, so a wrongly writable path is reported without being modified.

set -u

DIR=${MM_VERIFY_DIR:-/data/local/tmp/mm-verify}
BASE=$DIR/mountinfo
WORK=$DIR/tmp

PASS=0
FAIL=0
SKIP=0
INFO=0

ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  [SKIP] %s\n' "$*"; }
info() { INFO=$((INFO + 1)); printf '  [INFO] %s\n' "$*"; }

# A metamodule is installed under /data/adb/metamodule, a normal one under
# /data/adb/modules/<id>; the state files follow whichever exists.
mmdir() {
    for d in /data/adb/metamodule /data/adb/modules/magic_mount; do
        [ -d "$d" ] && { printf '%s\n' "$d"; return 0; }
    done
    return 1
}
sec()  { printf '\n== %s ==\n' "$*"; }

usage() {
    sed -n '5,12p' "$0" | sed 's/^# /  /; s/^#$/  /'
}

# Only the fields that describe the mount tree; mount IDs change per boot.
norm() {
    awk '{ print $3, $4, $5, $6 }' /proc/self/mountinfo | sort
}

# Magic mount hoists `system/<partition>/` onto `/<partition>/`; do the same
# so the sampled target is the path the module really covers.
target_of() {
    first=${1%%/*}
    case "$first" in
    vendor | product | system_ext | odm | oem)
        if [ -e "/$first" ]; then
            echo "/$1"
            return
        fi
        ;;
    esac
    echo "/system/$1"
}

# One enabled module file per module, as "target source" pairs.
collect_pairs() {
    for mod in /data/adb/modules/*; do
        [ -d "$mod/system" ] || continue
        [ -e "$mod/disable" ] && continue
        [ -e "$mod/skip_mount" ] && continue
        f=$(find "$mod/system" -type f 2>/dev/null | head -n 1)
        [ -n "$f" ] || continue
        rel=${f#"$mod/system/"}
        printf '%s %s\n' "$(target_of "$rel")" "$f"
    done | head -n 5
}

# The mount that really covers `path`.  magic_hide removes magic_mount's own
# mounts from mountinfo, so the deepest remaining ancestor directory is the
# identity a stock ROM reports there.  Comparing with the partition root is
# wrong on ROMs that stack another filesystem on top of it:
# `/product/overlay/*.apk` lives on an overlayfs mount with its own
# anonymous major:minor, not on `/product` itself.
expected_cover_of() {
    rp=$(readlink -f "$1" 2>/dev/null) || rp=$1
    printf '%s\n' "$rp" | awk '
        NR == FNR { target = $0; next }
        {
            mp = $5
            fs = ""
            for (i = 7; i <= NF; i++)
                if ($i == "-") { fs = $(i + 1); break }
            # A tmpfs ancestor is the magic_mount skeleton, never the stock
            # identity; on a symlinked partition its record name does not
            # match, so it can still be listed here.
            if (fs == "tmpfs")
                next
            if (mp == target)
                next
            if (mp == "/") {
                if (best == "") best = "/"
                next
            }
            n = length(mp)
            if (n >= length(target))
                next
            if (substr(target, 1, n) != mp)
                next
            if (substr(target, n + 1, 1) != "/")
                next
            if (n > len) {
                best = mp
                len = n
            }
        }
        END { print (best == "" ? "/" : best) }
    ' - /proc/self/mountinfo
}

# Zero-byte write attempt: succeeds only if the mount is writable.
try_write() {
    dd if=/dev/null of="$1" count=0 conv=notrunc 2>/dev/null
}

check_mount_table() {
    sec "mount table"
    info "mountinfo has $(wc -l < /proc/self/mountinfo) lines"

    if grep -E '(/debug_ramdisk|/sbin|/tmp)/(workdir|mm-)' \
        /proc/self/mountinfo >/dev/null 2>&1; then
        bad "private workspace is still mounted"
    else
        ok "no private workspace visible in mountinfo"
    fi

    if grep -Ei '/data/adb/modules|/adb/modules|APatch|KernelSU|Magisk' \
        /proc/mounts >/dev/null 2>&1; then
        bad "root-manager staging path or source name visible in /proc/mounts"
    else
        ok "no root-manager source/staging token in /proc/mounts"
    fi

    if [ -f "$BASE" ]; then
        norm >"$WORK"
        if cmp -s "$BASE" "$WORK"; then
            ok "mount table matches the saved baseline"
        else
            bad "mount table differs from the saved baseline"
            if command -v diff >/dev/null 2>&1; then
                diff "$BASE" "$WORK" 2>/dev/null | head -n 12 | sed 's/^/      /'
            fi
        fi
    else
        skip "no baseline; run --snapshot with the module disabled, then reboot"
    fi
}

# The hidden view has to equal a real mount namespace with our mountpoints
# detached; that donor namespace is what a device without the module reports.
# `loader donor-check` builds it with unshare + private propagation and
# compares the two tables, so a line that only exists because of us is caught.
check_donor() {
    sec "donor namespace (mountinfo parity)"

    d=$(mmdir) || { skip "module directory not found"; return; }
    loader=$d/lkm/loader
    if [ ! -x "$loader" ]; then
        skip "no loader at $loader"
        return
    fi
    if [ ! -r "$d/hide-records.map" ]; then
        skip "no hide-records.map yet (the mount stage has not published)"
        return
    fi

    out=$("$loader" donor-check 2>&1)
    rc=$?
    printf '%s\n' "$out" | head -n 12 | sed 's/^/      /'
    case "$rc" in
    0) ok "hidden mountinfo matches the donor namespace" ;;
    2) skip "donor namespace could not be built (unshare denied?)" ;;
    *) bad "hidden mountinfo differs from the donor namespace" ;;
    esac
}

# Cost of the hot path.  magic_hide intercepts stat()/statfs() for every
# process, so the per-call delta on a covered path is the number to compare
# across builds.  Informational: latency depends on the device and its load,
# so there is no threshold to fail on.
check_overhead() {
    sec "overhead (probe fast path)"

    d=$(mmdir) || { skip "module directory not found"; return; }
    loader=$d/lkm/loader
    if [ ! -x "$loader" ]; then
        skip "no loader at $loader"
        return
    fi

    out=$("$loader" bench 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        skip "bench could not run: $(printf '%s\n' "$out" | head -n 1)"
        return
    fi
    printf '%s\n' "$out" | head -n 8 | sed 's/^/      /'
    info "per-syscall cost above is informational"
}

check_hide() {
    sec "magic_hide"

    if [ -d /sys/module/magic_hide ]; then
        ok "magic_hide is loaded"
    else
        skip "magic_hide is not loaded (sysfs entry missing)"
    fi

    if grep -q magic_hide /proc/modules 2>/dev/null; then
        bad "/proc/modules still lists magic_hide"
    else
        ok "/proc/modules does not list magic_hide"
    fi

    # /sys/module is hidden by rewriting the kernfs readdir actor; the sysfs
    # directory itself stays reachable, which is why the load check above works.
    if [ -r /sys/module ] && ls /sys/module 2>/dev/null | grep -qx magic_hide; then
        bad "/sys/module lists magic_hide"
    else
        ok "/sys/module does not list magic_hide"
    fi

    # s_show drops every "symbol [magic_hide]" line from /proc/kallsyms.
    if [ -r /proc/kallsyms ]; then
        if grep -q '\[magic_hide\]' /proc/kallsyms 2>/dev/null; then
            bad "/proc/kallsyms still lists magic_hide symbols"
        else
            ok "/proc/kallsyms does not list magic_hide symbols"
        fi
    else
        skip "/proc/kallsyms not readable"
    fi

    if [ -r /sys/kernel/debug/kprobes/list ]; then
        if grep -E 'vfs_statfs|vfs_getattr|show_mountinfo|show_vfsmnt|show_vfsstat|m_show|show_kprobe_addr|s_show|kernfs_fop_readdir' \
            /sys/kernel/debug/kprobes/list >/dev/null 2>&1; then
            bad "our kprobes are listed in debugfs"
        else
            ok "no magic_hide probe in the debugfs kprobe list"
        fi
    else
        skip "debugfs kprobe list not readable (debugfs not mounted?)"
    fi

    if dmesg >/dev/null 2>&1; then
        published=$(dmesg 2>/dev/null | grep 'magic_hide: published' | tail -n 1)
        [ -n "$published" ] && info "$published"
        errs=$(dmesg 2>/dev/null | grep -E 'magic_hide: |magic_mount' \
            | grep -Ei 'fail|cannot|error|not found' | tail -n 5)
        if [ -n "$errs" ]; then
            bad "kernel log reports magic_hide/magic_mount errors"
            printf '%s\n' "$errs" | sed 's/^/      /'
        else
            ok "no magic_hide/magic_mount error in dmesg"
        fi
    else
        skip "dmesg not readable"
    fi
}

check_identity() {
    sec "identity (st_dev / zero-copy / capacity)"

    collect_pairs >"$WORK"
    if [ ! -s "$WORK" ]; then
        skip "no enabled module file to sample"
        return
    fi

    while read -r t src <&3; do
        [ -e "$t" ] || { skip "$t does not exist"; continue; }
        part=$(expected_cover_of "$t")

        d_t=$(stat -c %d "$t" 2>/dev/null)
        d_p=$(stat -c %d "$part" 2>/dev/null)
        if [ "$d_t" = "$d_p" ]; then
            ok "st_dev of $t matches its covering mount $part ($d_t)"
        else
            bad "st_dev of $t is $d_t, covering mount $part reports $d_p"
        fi

        # The target shares the module file's content, not its inode: magic_hide
        # now reports a stock-looking inode, so compare the file length instead.
        if [ -e "$src" ]; then
            s_t=$(stat -c %s "$t" 2>/dev/null)
            s_s=$(stat -c %s "$src" 2>/dev/null)
            if [ "$s_t" = "$s_s" ]; then
                ok "$t has the same length as $src ($s_t bytes)"
            else
                bad "$t is $s_t bytes, $src is $s_s"
            fi

            # A f2fs inode is an inode block address, far outside the range a
            # read-only partition uses; anything close to the module inode
            # means the forged value did not reach stat().
            i_t=$(stat -c %i "$t" 2>/dev/null)
            i_s=$(stat -c %i "$src" 2>/dev/null)
            if [ "$i_t" = "$i_s" ]; then
                bad "$t still reports the module inode $i_t"
            else
                ok "$t reports a forged stock inode $i_t"
            fi
        fi

        # A skeleton mount would report tmpfs here instead of the partition.
        m_t=$(stat -f -c %t "$t" 2>/dev/null)
        m_p=$(stat -f -c %t "$part" 2>/dev/null)
        if [ -n "$m_t" ] && [ -n "$m_p" ]; then
            if [ "$m_t" = "$m_p" ]; then
                ok "statfs type of $t matches its covering mount $part ($m_t)"
            else
                bad "statfs type of $t is $m_t, covering mount $part reports $m_p"
            fi
        fi

        # The statfs counters are forged from the covered partition, so the
        # skeleton must not advertise the tmpfs size here.
        b_t=$(df -k "$t" 2>/dev/null | awk 'NR==2 { print $2 }')
        b_p=$(df -k "$part" 2>/dev/null | awk 'NR==2 { print $2 }')
        if [ -n "$b_t" ] && [ -n "$b_p" ]; then
            if [ "$b_t" = "$b_p" ]; then
                ok "statfs capacity of $t matches its covering mount $part ($b_t 1K-blocks)"
            else
                bad "$t reports $b_t 1K-blocks, covering mount $part reports $b_p"
            fi
        fi
    done 3<"$WORK"
}

# Static per-boot timeline written by the Rust mount core; compare the digits
# across builds instead of guessing whether a change made boot slower.
check_timing() {
    sec "timing (mount stage timer)"

    f=$(mmdir)/mount-stats.txt
    if [ ! -r "$f" ]; then
        skip "no stage timing yet (reboot once after installing this build)"
        return
    fi
    while IFS= read -r line; do
        printf '      %s\n' "$line"
    done <"$f"

    summary=$(head -n 1 "$f")
    total=$(printf '%s\n' "$summary" | sed -n 's/.*total_us=\([0-9]*\).*/\1/p')
    count=$(printf '%s\n' "$summary" | sed -n 's/.*mountpoints=\([0-9]*\).*/\1/p')
    if [ -n "$total" ] && [ -n "$count" ] && [ "$count" -gt 0 ] 2>/dev/null; then
        info "$((total / count)) us per mountpoint ($count mountpoints)"
    fi
}

# Who asked for stat/statfs during boot.  The kernel records uid/pid/op/comm
# only for the boot window, then drops the probes, so this is a frozen snapshot
# rather than a live feed.
check_observers() {
    sec "observers (callers seen during boot)"

    f=$(mmdir)/hide-events.log
    if [ ! -r "$f" ]; then
        skip "no observer log (older build, or the observer never armed)"
        return
    fi
    sed -n '2,4p' "$f" | while IFS= read -r line; do printf '      %s\n' "$line"; done
    n=0
    while read -r uid pid op cnt comm; do
        case "$uid" in ''|'#'*) continue ;; esac
        n=$((n + 1))
        [ "$n" -le 8 ] || continue
        printf '      uid=%-6s pid=%-6s %-11s %8s  %s\n' "$uid" "$pid" "$op" "$cnt" "$comm"
    done <"$f"
    if [ "$n" -eq 0 ]; then
        skip "the observer table is empty"
    else
        info "$n distinct callers recorded"
    fi
}

# Which uids actually landed on a mountpoint we cover, plus the exemption
# suggestions derived from that table.  Both are written once at boot_completed.
check_hits() {
    sec "hits (callers that reached a covered mount)"

    d=$(mmdir)
    f=$d/hide-hits.log
    if [ -z "$d" ] || [ ! -r "$f" ]; then
        skip "no hit table (older build, or no hot lookup matched)"
        return
    fi
    n=0
    while read -r uid mount cnt comm; do
        case "$uid" in ''|'#'*) continue ;; esac
        n=$((n + 1))
        [ "$n" -le 8 ] || continue
        printf '      uid=%-6s %8s  %-40s %s\n' "$uid" "$cnt" "$mount" "$comm"
    done <"$f"
    if [ "$n" -eq 0 ]; then
        info "no covered mount was reached during boot"
    else
        info "$n uid/mount bucket(s) recorded"
    fi

    s=$d/hide-exempt-uids.suggested
    if [ -r "$s" ]; then
        m=$(grep -vc '^#' "$s" 2>/dev/null)
        info "${m:-0} exemption rule(s) suggested (not applied)"
        grep -v '^#' "$s" 2>/dev/null | head -5 | while read -r rule rest; do
            printf '      %s\n' "$rule"
        done
    fi
}

check_readonly() {
    sec "read-only behaviour (EROFS parity)"

    if [ "$(id -u)" != "0" ]; then
        skip "not root; write checks would report permissions, not EROFS"
    else
        collect_pairs >"$WORK"
        while read -r t src <&3; do
            [ -e "$t" ] || continue
            if try_write "$t" >/dev/null 2>&1; then
                bad "$t accepted an O_WRONLY open (should be EROFS)"
            else
                ok "$t rejects writes (EROFS)"
            fi
        done 3<"$WORK"

        for p in /system /vendor /product /system_ext /odm; do
            [ -d "$p" ] || continue
            probe="$p/.mm_verify_probe"
            if ( : >"$probe" ) 2>/dev/null; then
                rm -f "$probe"
                bad "$p allowed creating $probe"
            else
                ok "$p rejects creating files"
            fi
        done
    fi
}

check_cleanup() {
    sec "workspace / disk"

    for d in /debug_ramdisk/workdir /sbin/workdir /tmp/workdir; do
        if [ -e "$d" ]; then
            bad "leftover workspace path $d"
        else
            ok "no leftover $d"
        fi
    done

    # Placeholders are tmpfs inodes; nothing may appear below the module dirs.
    if [ -d /data/adb/modules ]; then
        if find /data/adb/modules -maxdepth 1 -name '.mm_verify*' 2>/dev/null | grep -q .; then
            bad "verification probe left inside /data/adb/modules"
        else
            ok "no probe artefacts inside /data/adb/modules"
        fi
    fi
}

case "${1:-}" in
--help | -h)
    usage
    exit 0
    ;;
--snapshot)
    mkdir -p "$DIR" || exit 2
    norm >"$BASE"
    printf 'baseline written to %s (%s lines)\n' "$BASE" "$(wc -l <"$BASE")"
    exit 0
    ;;
--diff)
    mkdir -p "$DIR" || exit 2
    check_mount_table
    printf '\n== summary ==\n  PASS %d  FAIL %d  SKIP %d\n' "$PASS" "$FAIL" "$SKIP"
    [ "$FAIL" -eq 0 ]
    exit
    ;;
"") ;;
*)
    usage >&2
    exit 2
    ;;
esac

mkdir -p "$DIR" || exit 2

printf 'magic_mount self check\n'

check_hide
check_mount_table
check_donor
check_overhead
check_identity
check_timing
check_observers
check_hits
check_readonly
check_cleanup

printf '\n== summary ==\n'
printf '  PASS %d  FAIL %d  SKIP %d  INFO %d\n' "$PASS" "$FAIL" "$SKIP" "$INFO"
printf '  workspace: %s\n' "$DIR"

[ "$FAIL" -eq 0 ]
