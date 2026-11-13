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
# kernel, and lkm.sh degrades silently when none matches.
if [ -d "$MODPATH/lkm" ]; then
	say "- LKM: $(cd "$MODPATH/lkm" && ls magic_hide*.ko 2>/dev/null | tr '\n' ' ')"
else
	say "! no lkm/ in this package: mounts will not be hidden"
fi

# Must stay last: install_module copies $MODPATH to /data, so anything created
# above (the partition links in particular) is only packaged if it runs after.
install_module
