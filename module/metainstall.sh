# Install script for root managers that support metamodules.
#
# The module id is magic_mount: KSU_METAMODULE has to match module.prop or the
# manager looks for a metamodule that does not exist.
export KSU_HAS_METAMODULE="true"
export KSU_METAMODULE="magic_mount"

say() {
	if type ui_print >/dev/null 2>&1; then
		ui_print "$@"
	else
		echo "$@"
	fi
}

# Overlay the directory instead of merging it, so a module that ships only
# part of a partition does not inherit the stock entries.
mark_replace() {
	replace_target="$1"
	mkdir -p "$replace_target"
	if command -v setfattr >/dev/null 2>&1; then
		setfattr -n trusted.overlay.opaque -v y "$replace_target" 2>/dev/null
	fi
}

# vendor, product, system_ext and odm live at the root of the tree in Android
# 10+, while modules ship them under system/.  Link them so the mount pass sees
# one layout regardless of how the partition was split.
handle_partitions() {
	partition="$1"

	if [ ! -d "$MODPATH/system/$partition" ]; then
		return
	fi

	if [ -L "/system/$partition" ] && [ -d "/$partition" ]; then
		say "- Handle partition /$partition"
		ln -sf "./system/$partition" "$MODPATH/$partition"
	fi
}

handle_partitions vendor
handle_partitions system_ext
handle_partitions product
handle_partitions odm

# Say which KMIs this package carries: the LKM only loads on a matching
# kernel, and lkm/loader degrades silently when none matches.
if [ -d "$MODPATH/lkm" ]; then
	say "- LKM: $(cd "$MODPATH/lkm" && ls magic_hide*.ko 2>/dev/null | tr '\n' ' ')"
else
	say "! no lkm/ in this package: mounts will not be hidden"
fi

# Remove everything the previous version installed that this zip does not
# ship: a .ko for a KMI that is no longer built, a script that was dropped, an
# old libmagic_mount.so.  Managers disagree on whether they wipe the module
# directory before copying, so the package's own file list is the source of
# truth.  Only files are removed; the manager's state flags survive.
clean_old_files() {
	target="$1"
	list="$MODPATH/files.list"

	[ -f "$list" ] || return 0
	[ -d "$target" ] || return 0
	# Never touch a directory that is not ours, whatever MODID says.
	[ -f "$target/module.prop" ] || return 0
	grep -qx 'id=magic_mount' "$target/module.prop" || return 0

	find "$target" -type f | while IFS= read -r path; do
		rel=${path#"$target"/}
		case "$rel" in
		files.list | module.prop | mount-stats.txt | mount-failures | disable | remove | skip_mount | update)
			continue
			;;
		esac
		grep -qxF "$rel" "$list" && continue
		rm -f "$path"
	done

	# Drop the now-empty directories too, or an old lkm/ layout would remain
	# visible in the installed module.
	find "$target" -mindepth 1 -depth -type d -empty -exec rmdir {} \; 2>/dev/null
	return 0
}

if [ -n "$MODPATH" ] && [ -d "$MODPATH" ]; then
	clean_old_files "${NVBASE:-/data/adb}/modules/${MODID:-magic_mount}"
fi

# Must stay last: install_module copies $MODPATH to /data, so anything created
# above (the partition links in particular) is only packaged if it runs after.
install_module

target="${NVBASE:-/data/adb}/modules/${MODID:-magic_mount}"

# Installing a new build is the user's way out of the safe-mode skip, so the
# consecutive-failure count starts from zero again.
rm -f "$target/mount-failures"

# The loader is executed directly by the metamodule; a zip that lost the mode
# would make lkm/loader exit 126 and the module would silently mount nothing.
chmod 755 "$MODPATH/lkm/loader" "$target/lkm/loader" 2>/dev/null
