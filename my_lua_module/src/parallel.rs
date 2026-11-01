//! Bounded work-scope parallelism for the mount walk.
//!
//! Mounting a module touches thousands of tiny, independent syscall jobs
//! (one bind per module file, one per mirrored entry).  The tree walk itself
//! has to stay ordered (a tmpfs skeleton must be filled before it is moved
//! onto its target), but the work inside a single directory - and the
//! subtrees of its children - is independent.
//!
//! `par_map` therefore runs a batch of owned jobs on a bounded set of
//! scoped threads.  The budget is process-global and non-blocking: nested
//! calls (a child directory spawning its own batch) only get the permits the
//! outer level did not take, and fall back to running inline when none are
//! left.  That keeps the total thread count at `MAX_THREADS` no matter how
//! deep the tree is, without needing an external runtime.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Upper bound for mount worker threads.  `mount(2)` is partially serialised
/// inside the kernel (namespace lock, security checks), so more threads stop
/// paying off quickly, while every extra thread costs memory on a phone.
const MAX_THREADS: usize = 8;

/// Batches smaller than this are not worth a thread hand-off.
const MIN_PARALLEL: usize = 4;

struct Budget {
    free: Mutex<usize>,
}

struct Permit {
    taken: usize,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.taken > 0 {
            *lock(&budget().free) += self.taken;
        }
    }
}

fn budget() -> &'static Budget {
    static BUDGET: OnceLock<Budget> = OnceLock::new();
    BUDGET.get_or_init(|| {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Budget {
            free: Mutex::new(cpus.clamp(1, MAX_THREADS)),
        }
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A worker panic is fatal anyway (it unwinds through thread::scope), so
    // poisoning only matters for diagnostics: keep using the data.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn take_permits(want: usize) -> Permit {
    let mut free = lock(&budget().free);
    let taken = (*free).min(want);
    *free -= taken;
    Permit { taken }
}

/// Map `items` through `f`, preserving order, using at most a handful of
/// scoped threads.  Every item is independent; `f` may itself call
/// `par_map` (it will degrade to inline execution once the budget is spent).
pub fn par_map<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let n = items.len();
    if n < MIN_PARALLEL {
        return items.into_iter().map(f).collect();
    }

    let want = n.min(MAX_THREADS);
    let permit = take_permits(want);
    if permit.taken == 0 {
        return items.into_iter().map(f).collect();
    }

    let slots: Mutex<Vec<Option<T>>> = Mutex::new(items.into_iter().map(Some).collect());
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..n).map(|_| None).collect());
    let cursor = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for _ in 0..permit.taken {
            scope.spawn(|| loop {
                let i = cursor.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                // The slot is only taken by the worker that owns this index.
                let item = lock(&slots)[i].take();
                let Some(item) = item else {
                    continue;
                };
                let value = f(item);
                lock(&results)[i] = Some(value);
            });
        }
    });
    drop(permit);

    lock(&results).drain(..).map(|r| r.expect("worker slot")).collect()
}
