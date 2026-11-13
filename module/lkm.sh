#!/system/bin/sh
#
# magic_mount: load the magic_hide GKI kernel module that matches this device.
#
# The module package ships one arm64 .ko per KMI under lkm/:
#
#   lkm/magic_hide-android12-5.10.ko
#   lkm/magic_hide-android13-5.15.ko
#   ...
#
# KMI detection, in order of confidence:
#
#   1. the kernel release string, which carries both halves of the KMI:
#        5.10.198-android12-9-00017-g...  ->  android12-5.10
#   2. the device platform release (ro.build.version.release), used only as
#      a tie-breaker when a custom kernel dropped the android tag;
#   3. the kernel major.minor, mapped to the KMIs that use it.
#
# Candidates are then tried exact-KMI first, then every .ko built for the
# same kernel major.minor, then a generic magic_hide.ko if one exists.
# insmod only succeeds for a matching vermagic, so this is best-effort:
# when nothing loads, magic_mount still mounts, only the extra VFS hiding
# is lost.

MODDIR=${0%/*}
LKM_DIR="$MODDIR/lkm"
LOG_TAG=magic_hide

msg() {
	log -t "$LOG_TAG" "$@" 2>/dev/null || echo "magic_hide: $*" >&2
}

# The module hides its own /proc/modules line, so /sys/module is the only
# reliable probe for "already loaded".
loaded() {
	[ -d /sys/module/magic_hide ] && return 0
	grep -q '^magic_hide ' /proc/modules 2>/dev/null
}

# Subcommands exist so the metamodule's action button and an uninstall can ask
# about (or drop) the module without duplicating the KMI logic above.
case "${1:-load}" in
status)
	printf 'kernel:  %s\n' "$(uname -r 2>/dev/null)"
	printf 'arch:    %s\n' "$(uname -m 2>/dev/null)"
	if loaded; then
		printf 'state:   loaded\n'
	else
		printf 'state:   not loaded\n'
	fi
	printf 'shipped:'
	if [ -d "$LKM_DIR" ]; then
		for f in "$LKM_DIR"/magic_hide*.ko; do
			[ -f "$f" ] || continue
			printf ' %s' "${f##*/}"
		done
		printf '\n'
	else
		printf ' (no lkm/ in the module)\n'
	fi
	printf 'stats:   %s\n' \
		"$(sed -n '1p' "$MODDIR/mount-stats.txt" 2>/dev/null || echo none)"
	exit 0
	;;
unload)
	# Only ever used for debugging: unloading while the mounts are still in
	# place exposes every module file, so a normal uninstall waits for reboot.
	loaded || { msg "not loaded"; exit 0; }
	RMMOD=$(command -v rmmod 2>/dev/null)
	[ -n "$RMMOD" ] || RMMOD=/system/bin/rmmod
	"$RMMOD" magic_hide 2>/dev/null && msg "unloaded magic_hide"
	exit 0
	;;
esac

[ -d "$LKM_DIR" ] || { msg "no lkm/ directory in the module"; exit 0; }
[ "$(id -u 2>/dev/null)" = "0" ] || exit 0
loaded && exit 0

INSMOD=$(command -v insmod 2>/dev/null)
[ -n "$INSMOD" ] || INSMOD=/system/bin/insmod
[ -x "$INSMOD" ] || { msg "insmod not found"; exit 0; }

case "$(uname -m)" in
aarch64 | arm64) ;;
*) exit 0 ;;
esac

RELEASE=$(uname -r 2>/dev/null)
VER=$(printf '%s\n' "$RELEASE" | grep -oE '[0-9]+\.[0-9]+' | head -n 1)
REL=$(printf '%s\n' "$RELEASE" | grep -oE 'android[0-9]+' | head -n 1)

# Tie-breaker for kernels without an android tag: the platform release maps
# one-to-one onto the GKI tag of the same number.
PLATFORM=""
if command -v getprop >/dev/null 2>&1; then
	PLATFORM=$(getprop ro.build.version.release 2>/dev/null | cut -d. -f1)
fi
case "${PLATFORM:-}" in
12 | 13 | 14 | 15 | 16) TAG="android$PLATFORM" ;;
*) TAG="" ;;
esac

KMI=""
[ -n "$REL" ] && KMI="$REL-$VER"
msg "release=$RELEASE version=${VER:-unknown} kmi=${KMI:-unknown}"

# KMIs that share one kernel major.minor.  Used when the release string has
# no android tag (custom kernels); the vermagic check still rejects the
# wrong one, this only saves attempts.
case "$VER" in
5.10) KMI_FAMILY="android12-5.10 android13-5.10" ;;
5.15) KMI_FAMILY="android13-5.15 android14-5.15" ;;
6.1) KMI_FAMILY="android14-6.1" ;;
6.6) KMI_FAMILY="android15-6.6" ;;
6.12) KMI_FAMILY="android16-6.12" ;;
*) KMI_FAMILY="" ;;
esac

# Candidate order: exact KMI, platform-tag guess, the same-version family,
# then every other .ko built for this kernel major.minor, then a generic one.
list_candidates() {
	[ -n "$KMI" ] && [ -f "$LKM_DIR/magic_hide-$KMI.ko" ] &&
		printf '%s\n' "$LKM_DIR/magic_hide-$KMI.ko"
	[ -n "$TAG" ] && [ -n "$VER" ] && [ -f "$LKM_DIR/magic_hide-$TAG-$VER.ko" ] &&
		printf '%s\n' "$LKM_DIR/magic_hide-$TAG-$VER.ko"
	for name in $KMI_FAMILY; do
		[ -f "$LKM_DIR/magic_hide-$name.ko" ] &&
			printf '%s\n' "$LKM_DIR/magic_hide-$name.ko"
	done
	for f in "$LKM_DIR"/magic_hide-*-"$VER".ko; do
		[ -f "$f" ] && printf '%s\n' "$f"
	done
	[ -f "$LKM_DIR/magic_hide.ko" ] && printf '%s\n' "$LKM_DIR/magic_hide.ko"
}

LIST=$(list_candidates)
[ -n "$LIST" ] || { msg "no .ko built for $RELEASE"; exit 0; }

TRIED=""
while IFS= read -r f; do
	[ -n "$f" ] || continue
	case "$TRIED" in
	*"$f"*) continue ;;
	esac
	TRIED="$TRIED$f
"

	ERR=$("$INSMOD" "$f" 2>&1)
	OK=$?
	if [ "$OK" -eq 0 ] && loaded; then
		msg "loaded ${f##*/} (kmi ${KMI:-$TAG})"
		exit 0
	fi
	# A concurrent loader (or a retry) may have loaded it already.
	if loaded; then
		msg "${f##*/}: already loaded"
		exit 0
	fi
	msg "insmod ${f##*/} failed: ${ERR:-unknown} (see: dmesg | grep magic_hide)"
done <<EOF
$LIST
EOF

msg "no compatible .ko for $RELEASE"
exit 0
