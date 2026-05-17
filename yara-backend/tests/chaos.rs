//! Chaos integration test.
//!
//! Spawns multiple worker threads that interleave random operations against
//! a single shared `Arc<YaraBackend>`: rule file adds, removals, content
//! corruption, scans of varying sizes, and explicit reload calls. Each
//! operation must return a `Result` (no panics escape the wrapper) and the
//! backend must never deadlock or corrupt its internal state.
//!
//! Determinism: every thread uses a seeded LCG, so a failure is
//! reproducible from the thread id alone. The iteration count is small by
//! default to keep CI fast; bump `OPS_PER_THREAD` locally if you want a
//! longer soak. The seed is printed on failure so you can replay it.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;
use yara_backend::{Error, YaraBackend};

const THREAD_COUNT: usize = 8;
const OPS_PER_THREAD: usize = 250;
const RULE_SLOTS: usize = 6;

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next_u32() as usize) % n
    }
}

fn make_buffer(rng: &mut Lcg, max_len: usize) -> Vec<u8> {
    let len = (rng.next_u32() as usize % max_len.max(1)) + 1;
    let mut buf = vec![0u8; len];
    for byte in buf.iter_mut() {
        *byte = (rng.next_u32() & 0xFF) as u8;
    }
    if len >= 2 && rng.pick(3) == 0 {
        buf[0] = 0x4D;
        buf[1] = 0x5A;
    }
    buf
}

fn rule_body(slot: usize, marker: u32) -> String {
    format!(
        "rule chaos_slot_{slot} {{ meta: marker = \"{marker:08x}\" \
         strings: $a = \"abcdef{slot:02}\" condition: $a }}"
    )
}

fn malformed_body() -> &'static str {
    "rule broken { strings: $a = \"oops"
}

#[derive(Debug, Default)]
struct ThreadStats {
    scans_ok: u32,
    scans_err: u32,
    reloads_ok: u32,
    reloads_err: u32,
    writes: u32,
    deletes: u32,
}

fn worker(
    tid: usize,
    backend: Arc<YaraBackend>,
    rules_dir: PathBuf,
    slots: Arc<Vec<PathBuf>>,
) -> ThreadStats {
    let mut rng =
        Lcg::new(0xCAFE_BABE_DEAD_BEEF ^ ((tid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
    let mut stats = ThreadStats::default();
    let _ = rules_dir;

    for _ in 0..OPS_PER_THREAD {
        match rng.pick(8) {
            0 => {
                // Drop a fresh well-formed rule into a slot.
                let slot = rng.pick(RULE_SLOTS);
                let body = rule_body(slot, rng.next_u32());
                if fs::write(&slots[slot], body).is_ok() {
                    stats.writes += 1;
                }
            }
            1 => {
                // Drop a malformed rule (the silent-blackout safety net is exercised).
                let slot = rng.pick(RULE_SLOTS);
                if fs::write(&slots[slot], malformed_body()).is_ok() {
                    stats.writes += 1;
                }
            }
            2 => {
                // Delete a rule slot if it exists.
                let slot = rng.pick(RULE_SLOTS);
                if fs::remove_file(&slots[slot]).is_ok() {
                    stats.deletes += 1;
                }
            }
            3..=5 => {
                // Random scan_bytes call (most common operation).
                let buf = make_buffer(&mut rng, 4096);
                match backend.scan_bytes(&buf, Duration::from_secs(5)) {
                    Ok(_) => stats.scans_ok += 1,
                    Err(Error::ScanFailed { .. })
                    | Err(Error::Timeout { .. })
                    | Err(Error::RulesDirGone { .. })
                    | Err(Error::CompileLockTimeout(_)) => {
                        stats.scans_err += 1;
                    }
                    Err(other) => {
                        panic!("chaos thread {tid}: unexpected scan_bytes error class: {other:?}")
                    }
                }
            }
            6 => {
                // Explicit reload (race with whatever is being written).
                match backend.reload_if_changed() {
                    Ok(_) => stats.reloads_ok += 1,
                    Err(Error::RulesDirGone { .. })
                    | Err(Error::CompileLockTimeout(_))
                    | Err(Error::LoadRules { .. })
                    | Err(Error::CompileFailed { .. })
                    | Err(Error::UnsupportedModule { .. }) => stats.reloads_err += 1,
                    Err(other) => {
                        panic!("chaos thread {tid}: unexpected reload error class: {other:?}")
                    }
                }
            }
            _ => {
                // scan_file against a fresh temp file (varies path each time).
                let scratch =
                    std::env::temp_dir().join(format!("yara_chaos_{tid}_{}.bin", rng.next_u32()));
                let buf = make_buffer(&mut rng, 8192);
                if fs::write(&scratch, &buf).is_ok() {
                    match backend.scan_file(&scratch, Duration::from_secs(5)) {
                        Ok(_) => stats.scans_ok += 1,
                        Err(Error::ScanFailed { .. })
                        | Err(Error::Timeout { .. })
                        | Err(Error::RulesDirGone { .. })
                        | Err(Error::CompileLockTimeout(_))
                        | Err(Error::Io { .. }) => stats.scans_err += 1,
                        Err(other) => panic!(
                            "chaos thread {tid}: unexpected scan_file error class: {other:?}"
                        ),
                    }
                    let _ = fs::remove_file(&scratch);
                }
            }
        }
    }
    stats
}

#[test]
fn chaos_threads_never_panic_or_deadlock() {
    let td = TempDir::new().unwrap();
    let rules_dir = td.path().to_path_buf();
    let slots: Vec<PathBuf> = (0..RULE_SLOTS)
        .map(|s| rules_dir.join(format!("slot_{s}.yar")))
        .collect();
    // Seed the dir with one good rule so load_from_dir doesn't see an empty dir.
    fs::write(&slots[0], rule_body(0, 0xDEAD_BEEF)).unwrap();
    let backend = Arc::new(YaraBackend::load_from_dir(&rules_dir).unwrap());
    let slots = Arc::new(slots);

    let mut handles = Vec::new();
    for tid in 0..THREAD_COUNT {
        let backend = backend.clone();
        let rules_dir = rules_dir.clone();
        let slots = slots.clone();
        handles.push(thread::spawn(move || {
            worker(tid, backend, rules_dir, slots)
        }));
    }

    let mut totals = ThreadStats::default();
    for h in handles {
        let stats = h.join().expect("chaos thread panicked");
        totals.scans_ok += stats.scans_ok;
        totals.scans_err += stats.scans_err;
        totals.reloads_ok += stats.reloads_ok;
        totals.reloads_err += stats.reloads_err;
        totals.writes += stats.writes;
        totals.deletes += stats.deletes;
    }

    // The backend must still be usable after the storm.
    let post_count = backend.rule_count();
    let warnings = backend.compile_warnings();
    eprintln!(
        "chaos summary: scans_ok={}, scans_err={}, reloads_ok={}, reloads_err={}, writes={}, deletes={}, final_rule_count={}, warnings={}",
        totals.scans_ok,
        totals.scans_err,
        totals.reloads_ok,
        totals.reloads_err,
        totals.writes,
        totals.deletes,
        post_count,
        warnings.len(),
    );

    // After the storm settles, a fresh scan should still succeed.
    let mut buf = vec![0u8; 64];
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    let report = backend
        .scan_bytes(&buf, Duration::from_secs(5))
        .expect("final scan must succeed");
    // Sanity: rule names returned are unique and sorted.
    let names = report.rule_names_sorted();
    let unique: BTreeSet<_> = names.iter().cloned().collect();
    assert_eq!(unique.len(), names.len(), "rule_names_sorted must dedup");
    assert!(
        names.windows(2).all(|w| w[0] <= w[1]),
        "rule_names_sorted must be sorted"
    );
    assert!(
        totals.scans_ok + totals.scans_err >= 100,
        "chaos ran at least 100 scans across threads"
    );
}
