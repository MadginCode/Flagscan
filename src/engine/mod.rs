//! Recursive, chained scan engine.
//!
//! Every input file becomes a root `Node`. Each node is searched for flags (directly and through
//! byte-wise ciphers), then every enabled module may derive child nodes from it (decoded base64,
//! archive members, LSB planes, carved files...). Children go back into a breadth-first queue, so
//! transformations chain arbitrarily up to `max_depth`, and every finding carries the full chain.

pub mod bytemaps;
pub mod carve;
pub mod containers;
pub mod encodings;
pub mod formats;
pub mod stego;
pub mod http;
pub mod tools;
pub mod qr;
pub mod report;
pub mod util;

use crate::config::{FlagMatcher, ScanConfig};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Flags carried down a chain to stop pointless re-application of the same transform.
#[derive(Clone, Copy, Default, Debug)]
pub struct Origin {
    pub lsb: bool,
    pub reversed: bool,
    pub rot13: bool,
    pub xored: bool,
    /// Text produced by a lossy "extract strings" step; skip binary-oriented modules on it.
    pub text_only: bool,
}

pub struct Node {
    pub data: Vec<u8>,
    pub chain: Vec<String>,
    pub depth: usize,
    pub origin: Origin,
}

/// A derived blob proposed by a module.
pub struct Child {
    pub label: String,
    pub data: Vec<u8>,
    pub origin: Origin,
    /// Save to the artifacts list so it can be downloaded from the UI.
    pub artifact: bool,
}

impl Child {
    pub fn new(label: impl Into<String>, data: Vec<u8>) -> Self {
        Self { label: label.into(), data, origin: Origin::default(), artifact: false }
    }
    pub fn artifact(mut self) -> Self {
        self.artifact = true;
        self
    }
    pub fn with_origin(mut self, o: Origin) -> Self {
        self.origin = o;
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub flag: String,
    /// Shortest few chains that produced this flag.
    pub chains: Vec<Vec<String>>,
    pub offset: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Note {
    pub chain: Vec<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactInfo {
    pub id: usize,
    pub name: String,
    pub chain: Vec<String>,
    pub size: usize,
    pub kind: String,
    #[serde(skip)]
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Stats {
    pub state: String,
    pub files_total: usize,
    pub files_done: usize,
    pub nodes: usize,
    pub bytes: u64,
    pub current: String,
    pub elapsed_ms: u128,
    pub error: Option<String>,
    pub budget_hit: bool,
}

/// Per-input-file triage: what the file is and whether it looks encrypted/compressed.
#[derive(Clone, Debug, Serialize)]
pub struct Triage {
    pub name: String,
    pub size: u64,
    pub kind: String,
    pub sha256: String,
    /// Shannon entropy in bits per byte (8.0 = indistinguishable from random).
    pub entropy: f64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub notes: Vec<Note>,
    pub artifacts: Vec<ArtifactInfo>,
    pub triage: Vec<Triage>,
    pub stats: Stats,
}

impl ScanResult {
    fn add_finding(&mut self, flag: String, chain: Vec<String>, offset: usize) {
        if let Some(f) = self.findings.iter_mut().find(|f| f.flag == flag) {
            if f.chains.len() < 5 && !f.chains.contains(&chain) {
                f.chains.push(chain);
                f.chains.sort_by_key(|c| c.len());
            }
            return;
        }
        self.findings.push(Finding { flag, chains: vec![chain], offset });
        self.findings.sort_by_key(|f| f.chains[0].len());
    }
}

/// Shared handle used by both CLI and web jobs. Hot counters live in atomics so parallel
/// workers don't contend on the result mutex for every node.
pub struct Job {
    pub result: Mutex<ScanResult>,
    pub cancel: AtomicBool,
    pub artifact_dir: Option<PathBuf>,
    pub started: Instant,
    pub nodes: AtomicUsize,
    pub bytes: AtomicU64,
    pub files_done: AtomicUsize,
    /// Precomputed once (includes any wordlist) and shared by every worker.
    pub passwords: Vec<Vec<u8>>,
}

impl Job {
    pub fn with_passwords(artifact_dir: Option<PathBuf>, passwords: Vec<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(ScanResult::default()),
            cancel: AtomicBool::new(false),
            artifact_dir,
            started: Instant::now(),
            nodes: AtomicUsize::new(0),
            bytes: AtomicU64::new(0),
            files_done: AtomicUsize::new(0),
            passwords,
        })
    }
    pub fn snapshot(&self) -> ScanResult {
        let mut r = self.result.lock().unwrap().clone();
        r.stats.nodes = self.nodes.load(Ordering::Relaxed);
        r.stats.bytes = self.bytes.load(Ordering::Relaxed);
        r.stats.files_done = self.files_done.load(Ordering::Relaxed);
        r.stats.elapsed_ms = self.started.elapsed().as_millis();
        r
    }
}

pub struct Scanner<'a> {
    pub cfg: &'a ScanConfig,
    pub matcher: &'a FlagMatcher,
    job: &'a Job,
    seen: HashSet<[u8; 16]>,
    pub passwords: &'a [Vec<u8>],
    /// When the current file must be abandoned (per-file timeout).
    deadline: Option<Instant>,
}

const MAX_ARTIFACTS: usize = 2000;
const MAX_CHILDREN_PER_NODE: usize = 512;

/// Collect files, set up the shared job, and scan them (in parallel across files). Used by both
/// the CLI and the web server. `display_root` strips a prefix from reported names.
pub fn run(cfg: &ScanConfig, matcher: &FlagMatcher, job: &Job, paths: &[PathBuf], display_root: Option<&Path>) {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            for e in walkdir::WalkDir::new(p).follow_links(false).into_iter().flatten() {
                if e.file_type().is_file() {
                    files.push(e.into_path());
                }
            }
        } else {
            files.push(p.clone());
        }
    }
    files.sort();
    let auto_root = match (display_root, paths) {
        (None, [one]) => one.parent().map(Path::to_path_buf),
        _ => None,
    };
    let display_root = display_root.or(auto_root.as_deref());
    {
        let mut r = job.result.lock().unwrap();
        r.stats.state = "running".into();
        r.stats.files_total = files.len();
    }

    let next = AtomicUsize::new(0);
    let workers = if cfg.threads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) } else { cfg.threads }
        .clamp(1, 64)
        .min(files.len().max(1));
    let timeout = (cfg.file_timeout_ms > 0).then(|| Duration::from_millis(cfg.file_timeout_ms));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let (next, files, display_root) = (&next, &files, display_root);
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(f) = files.get(i) else { break };
                    if job.cancel.load(Ordering::Relaxed) || job.nodes.load(Ordering::Relaxed) >= cfg.max_nodes {
                        continue;
                    }
                    let name = display_root.and_then(|r| f.strip_prefix(r).ok()).unwrap_or(f).to_string_lossy().into_owned();
                    {
                        job.result.lock().unwrap().stats.current = name.clone();
                    }
                    let mut sc = Scanner {
                        cfg,
                        matcher,
                        job,
                        seen: HashSet::new(),
                        passwords: &job.passwords,
                        deadline: timeout.map(|d| Instant::now() + d),
                    };
                    match std::fs::metadata(f) {
                        Ok(m) if m.len() > cfg.max_file_size => {
                            sc.note(vec![name.clone()], format!("skipped: {} bytes exceeds max file size", m.len()));
                        }
                        Ok(_) => match std::fs::read(f) {
                            Ok(data) => {
                                sc.triage(&name, &data);
                                sc.scan_root(name.clone(), data);
                            }
                            Err(e) => sc.note(vec![name.clone()], format!("cannot read: {e}")),
                        },
                        Err(e) => sc.note(vec![name.clone()], format!("cannot stat: {e}")),
                    }
                    job.files_done.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });

    let cancelled = job.cancel.load(Ordering::Relaxed);
    let mut r = job.result.lock().unwrap();
    r.stats.state = if cancelled { "cancelled".into() } else { "done".into() };
    r.stats.current.clear();
    r.stats.elapsed_ms = job.started.elapsed().as_millis();
    r.stats.nodes = job.nodes.load(Ordering::Relaxed);
    r.stats.bytes = job.bytes.load(Ordering::Relaxed);
    r.stats.files_done = job.files_done.load(Ordering::Relaxed);
}

impl<'a> Scanner<'a> {

    fn update(&self, f: impl FnOnce(&mut ScanResult)) {
        f(&mut self.job.result.lock().unwrap());
    }

    /// Record a top-level file's type, hash and entropy, and flag likely crypto.
    fn triage(&self, name: &str, data: &[u8]) {
        let kind = util::sniff(data).unwrap_or(if util::printable_ratio(data) > 0.9 { "text" } else { "data" });
        let entropy = shannon_entropy(data);
        let sha256 = {
            let h = Sha256::digest(data);
            h.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        // A high-entropy blob that isn't a known compressed/image format is probably encrypted.
        if entropy > 7.8 && matches!(kind, "data") && data.len() >= 256 {
            self.note(vec![name.into()], format!("high entropy ({entropy:.2} bits/byte) with no known header: likely encrypted or raw-compressed"));
        }
        self.update(|r| r.triage.push(Triage { name: name.into(), size: data.len() as u64, kind: kind.into(), sha256, entropy }));
    }

    pub fn note(&self, chain: Vec<String>, message: String) {
        self.update(|r| {
            if r.notes.len() < 5000 && !r.notes.iter().any(|n| n.chain == chain && n.message == message) {
                r.notes.push(Note { chain, message });
            }
        });
    }

    fn add_flag(&self, flag: String, chain: Vec<String>, offset: usize) {
        self.update(|r| r.add_finding(flag, chain, offset));
    }

    fn save_artifact(&self, chain: &[String], data: &[u8], kind: &str) {
        let Some(dir) = &self.job.artifact_dir else { return };
        let mut r = self.job.result.lock().unwrap();
        if r.artifacts.len() >= MAX_ARTIFACTS || r.artifacts.iter().any(|a| a.chain == chain) {
            return;
        }
        let id = r.artifacts.len();
        let last = chain.last().cloned().unwrap_or_default();
        let name = util::sanitize_name(&last, data);
        let path = dir.join(format!("{id:05}_{name}"));
        if std::fs::write(&path, data).is_ok() {
            r.artifacts.push(ArtifactInfo { id, name, chain: chain.to_vec(), size: data.len(), kind: kind.into(), path });
        }
    }

    fn digest(data: &[u8]) -> [u8; 16] {
        let h = Sha256::digest(data);
        let mut out = [0u8; 16];
        out.copy_from_slice(&h[..16]);
        out
    }

    pub fn scan_root(&mut self, name: String, data: Vec<u8>) {
        let mut queue = VecDeque::new();
        self.seen.insert(Self::digest(&data));
        queue.push_back(Node { data, chain: vec![name.clone()], depth: 0, origin: Origin::default() });
        while let Some(node) = queue.pop_front() {
            if self.job.cancel.load(Ordering::Relaxed) {
                return;
            }
            if self.deadline.is_some_and(|d| Instant::now() >= d) {
                self.note(vec![name], format!("timed out after {} ms; this file was only partly scanned", self.cfg.file_timeout_ms));
                return;
            }
            if self.job.nodes.fetch_add(1, Ordering::Relaxed) >= self.cfg.max_nodes {
                self.update(|r| r.stats.budget_hit = true);
                self.note(node.chain.clone(), "node budget reached; deeper layers were skipped".into());
                return;
            }
            self.job.bytes.fetch_add(node.data.len() as u64, Ordering::Relaxed);
            let children = self.process(&node);
            if node.depth + 1 > self.cfg.max_depth {
                continue;
            }
            for c in children.into_iter().take(MAX_CHILDREN_PER_NODE) {
                if c.data.is_empty() || c.data.len() > self.cfg.max_node_size {
                    continue;
                }
                if !self.seen.insert(Self::digest(&c.data)) {
                    continue;
                }
                let mut chain = node.chain.clone();
                chain.push(c.label);
                if c.artifact {
                    let kind = util::sniff(&c.data).unwrap_or(if util::printable_ratio(&c.data) > 0.9 { "text" } else { "data" });
                    self.save_artifact(&chain, &c.data, kind);
                }
                let mut origin = c.origin;
                origin.lsb |= node.origin.lsb;
                origin.reversed |= node.origin.reversed;
                origin.rot13 |= node.origin.rot13;
                origin.xored |= node.origin.xored;
                queue.push_back(Node { data: c.data, chain, depth: node.depth + 1, origin });
            }
        }
    }

    /// Search one node for flags and return derived children.
    fn process(&mut self, node: &Node) -> Vec<Child> {
        let data = &node.data;
        let transformed_text = node.origin.reversed || node.origin.rot13;
        let direct = if transformed_text { self.matcher.find_all_strict(data) } else { self.matcher.find_all(data) };
        for (off, flag) in direct {
            self.add_flag(flag, node.chain.clone(), off);
        }
        let m = &self.cfg.modules;
        if m.xor || m.rot {
            for hit in bytemaps::scan(data, self.matcher, m.xor && !node.origin.xored, m.rot) {
                // rot13 of a rot13 child is just the parent again.
                if node.origin.rot13 && hit.transform.starts_with("caesar shift 13") {
                    continue;
                }
                let mut chain = node.chain.clone();
                chain.push(hit.transform);
                self.add_flag(hit.flag, chain, hit.offset);
            }
        }

        let mut kids: Vec<Child> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        let kind = util::sniff(data);

        if !node.origin.text_only {
            if m.archives {
                containers::expand(self, data, kind, &mut kids, &mut notes);
            }
            if m.metadata {
                formats::expand(data, kind, &mut kids, &mut notes);
            }
            if m.stego && !node.origin.lsb {
                stego::expand(data, kind, &mut kids, &mut notes);
            }
            if m.qr {
                qr::expand(data, kind, &mut kids, &mut notes);
            }
            if m.carving {
                carve::expand(data, kind, self.cfg.max_node_size, &mut kids);
            }
            if m.xor && !node.origin.xored {
                bytemaps::xor_magic_children(data, kind, &mut kids);
            }
        }
        if m.encodings {
            encodings::expand(data, &mut kids);
        }
        if m.rot {
            let texty = util::printable_ratio(data) > 0.85;
            if !node.origin.reversed && data.len() >= 8 && data.len() <= 16 * 1024 * 1024 && (texty || node.depth == 0) {
                let mut r = data.clone();
                r.reverse();
                let mut c = Child::new("reverse", r);
                c.origin.reversed = true;
                kids.push(c);
            }
            if texty && !node.origin.rot13 && data.iter().filter(|b| b.is_ascii_alphabetic()).count() >= 8 {
                let mut c = Child::new("rot13", bytemaps::rot13(data));
                c.origin.rot13 = true;
                kids.push(c);
            }
        }
        for n in notes {
            self.note(node.chain.clone(), n);
        }
        kids
    }
}

/// Shannon entropy over the first 256 KiB, in bits per byte.
fn shannon_entropy(data: &[u8]) -> f64 {
    let data = &data[..data.len().min(256 * 1024)];
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    -counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        p * p.log2()
    }).sum::<f64>()
}

/// Convenience used by the CLI and tests: scan paths synchronously and return the result.
pub fn scan_blocking(cfg: &ScanConfig, paths: &[PathBuf], artifact_dir: Option<PathBuf>) -> anyhow::Result<ScanResult> {
    let matcher = FlagMatcher::new(cfg)?;
    let job = Job::with_passwords(artifact_dir, cfg.all_passwords());
    run(cfg, &matcher, &job, paths, None);
    Ok(job.snapshot())
}
