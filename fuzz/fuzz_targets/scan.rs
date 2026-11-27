//! Fuzz every parser at once: feed arbitrary bytes in as a single "file" and run the scan engine
//! with a tight budget. A crash here is a panic in one of the format/decoder parsers.
//!
//! Run with: cargo +nightly fuzz run scan
#![no_main]

use flagscan::config::ScanConfig;
use flagscan::engine;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cfg = ScanConfig {
        // Keep the recursion cheap so the fuzzer explores parsers, not depth.
        max_nodes: 1500,
        max_depth: 6,
        max_node_size: 2 << 20,
        max_file_size: 8 << 20,
        generic: true, // exercise the brute-force transform paths too
        ..Default::default()
    };
    let _ = engine::scan_bytes(&cfg, "fuzz", data.to_vec());
});
