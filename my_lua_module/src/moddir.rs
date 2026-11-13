//! Where this module's own files live.
//!
//! A metamodule is not installed under /data/adb/modules/<id>: APatch keeps it
//! in /data/adb/metamodule and hands the path to Lua as MODDIR.  The Rust side
//! writes hidden state (mount-stats.txt, hide-events.log, hide-hits.log,
//! hide-exempt-uids and its suggestion draft)
//! next to the module, so it has to learn that path instead of assuming the
//! Magisk layout.  Defaults to the Magisk layout when nothing was configured.

use std::path::PathBuf;
use std::sync::RwLock;

const DEFAULT_DIR: &str = "/data/adb/modules/magic_mount";

static DIR: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn set(dir: &str) {
    if dir.is_empty() {
        return;
    }
    if let Ok(mut slot) = DIR.write() {
        *slot = Some(PathBuf::from(dir));
    }
}

pub fn path() -> PathBuf {
    DIR.read()
        .ok()
        .and_then(|slot| slot.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}
