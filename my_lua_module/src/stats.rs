//! Low-overhead stage timing for the mount run.
//!
//! The mount path is a straight sequence of phases, so one `Instant::now()`
//! per phase is enough to turn "boot feels slow" into numbers that can be
//! compared across builds.  The result is one small file per boot:
//!
//! ```text
//! magic_mount timings total_us=... mountpoints=...
//!   stage=collect us=...
//!   ...
//! ```
//!
//! Each stage is the wall time since the previous mark, so the digits add up
//! to the total.  Nothing is printed to dmesg: a log line naming the module
//! would itself be a fingerprint.

use crate::moddir;
use std::io::Write;
use std::time::Instant;

pub struct StageTimer {
    started: Instant,
    last: Instant,
    stages: Vec<(&'static str, u128)>,
}

impl StageTimer {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last: now,
            stages: Vec::with_capacity(8),
        }
    }

    /// Close the current stage.  Costs one clock read and one push.
    pub fn mark(&mut self, name: &'static str) {
        let now = Instant::now();
        self.stages
            .push((name, now.duration_since(self.last).as_micros()));
        self.last = now;
    }

    /// Write the timeline next to the module.  Failures are ignored: timing
    /// must never affect the mount result.
    pub fn finish(&self, mountpoints: usize) {
        let mut text = String::with_capacity(192);
        text.push_str(&format!(
            "magic_mount timings total_us={} mountpoints={mountpoints}\n",
            self.started.elapsed().as_micros()
        ));
        for (name, us) in &self.stages {
            text.push_str(&format!("  stage={name} us={us}\n"));
        }
        if let Ok(mut file) = std::fs::File::create(moddir::path().join("mount-stats.txt")) {
            let _ = file.write_all(text.as_bytes());
        }
    }
}
