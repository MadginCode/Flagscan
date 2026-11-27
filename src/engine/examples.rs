//! Built-in example challenges, embedded in the binary so anyone can try flagscan (or check that
//! it works on their machine) without hunting for CTF files. Regenerate with examples/build.py.

use super::ScanResult;
use crate::config::ScanConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

const BUNDLE: &[u8] = include_bytes!("../../examples/examples.tar.gz");
const MANIFEST: &str = include_str!("../../examples/manifest.json");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Example {
    pub file: String,
    pub technique: String,
    /// The flag a scan should find; None for visual examples you inspect in the Stego tools.
    pub flag: Option<String>,
    pub visual: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub wordlist: String,
    pub examples: Vec<Example>,
}

pub fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST).expect("embedded examples manifest is valid JSON")
}

/// Write every example into `dir` (created if needed). Paths come from our own bundle, and the
/// tar crate's `unpack` refuses entries that would land outside `dir`.
pub fn extract(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    tar::Archive::new(flate2::read::GzDecoder::new(BUNDLE))
        .unpack(dir)
        .with_context(|| format!("extracting examples into {}", dir.display()))
}

/// Read one example file straight from the bundle (for the web UI's viewers).
pub fn read(name: &str) -> Option<Vec<u8>> {
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(BUNDLE));
    for e in ar.entries().ok()?.flatten() {
        let mut e = e;
        if e.path().ok()?.to_string_lossy() == name {
            let mut v = Vec::new();
            e.read_to_end(&mut v).ok()?;
            return Some(v);
        }
    }
    None
}

/// Fixed settings for scanning the examples, independent of the user's saved config, so the
/// result is the same on every machine.
pub fn config(dir: &Path) -> ScanConfig {
    ScanConfig {
        formats: vec!["flag{}".into()],
        case_insensitive: true,
        wordlist: dir.join(manifest().wordlist).to_string_lossy().into_owned(),
        ..Default::default()
    }
}

/// For each example with a flag: was it found?
pub fn check(res: &ScanResult) -> Vec<(Example, bool)> {
    manifest()
        .examples
        .into_iter()
        .filter(|e| e.flag.is_some())
        .map(|e| {
            let found = res.findings.iter().any(|f| Some(&f.flag) == e.flag.as_ref());
            (e, found)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_matches_manifest() {
        let m = manifest();
        let dir = tempfile::tempdir().unwrap();
        extract(dir.path()).unwrap();
        for e in &m.examples {
            assert!(dir.path().join(&e.file).is_file(), "missing {}", e.file);
        }
        assert!(dir.path().join(&m.wordlist).is_file());
        assert!(read("01_plain.txt").is_some());
    }

    /// The real self-test: scanning the bundle must find every listed flag.
    #[test]
    fn every_example_flag_is_found() {
        let dir = tempfile::tempdir().unwrap();
        extract(dir.path()).unwrap();
        let res = super::super::scan_blocking(&config(dir.path()), &[dir.path().to_path_buf()], None).unwrap();
        let missed: Vec<_> = check(&res).into_iter().filter(|(_, ok)| !ok).map(|(e, _)| e.file).collect();
        assert!(missed.is_empty(), "examples not solved: {missed:?}");
    }
}
