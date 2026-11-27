//! Find files embedded inside other files by magic bytes (binwalk-style), at any offset > 0.

use super::{Child, containers, util};
use memchr::memmem;

const SIGS: &[(&str, &[u8])] = &[
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF89a"),
    ("gif", b"GIF87a"),
    ("pdf", b"%PDF-"),
    ("zip", b"PK\x03\x04"),
    ("gzip", b"\x1f\x8b\x08"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\0"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("rar", b"Rar!\x1a\x07"),
    ("elf", b"\x7fELF"),
    ("wav", b"RIFF"),
    ("bmp", b"BM"),
    ("zlib", b"\x78\x9c"),
    ("zlib", b"\x78\xda"),
    ("zlib", b"\x78\x01"),
];

const MAX_CARVES: usize = 64;

pub fn expand(data: &[u8], kind: Option<&str>, limit: usize, kids: &mut Vec<Child>) {
    let mut found: Vec<(usize, &str)> = Vec::new();
    for (k, sig) in SIGS {
        // Members of a zip all start with PK\x03\x04: only carve zips out of non-zip hosts,
        // and only the first header. Same idea for nested deflate streams inside containers
        // that we already decode natively.
        if (*k == "zip" && kind == Some("zip")) || (*k == "zlib" && matches!(kind, Some("png" | "pdf" | "zip" | "gzip"))) {
            continue;
        }
        let mut first_zip = true;
        for off in memmem::find_iter(data, sig) {
            if off == 0 {
                continue;
            }
            let rest = &data[off..];
            let valid = match *k {
                "jpeg" => rest.len() > 4 && (rest[3] & 0xf0 == 0xe0 || rest[3] == 0xdb || rest[3] == 0xee),
                "bzip2" => rest.len() > 10 && (b'1'..=b'9').contains(&rest[3]) && &rest[4..10] == b"1AY&SY",
                "wav" => util::sniff(rest) == Some("wav") || util::sniff(rest) == Some("webp"),
                "bmp" => util::sniff(rest) == Some("bmp") && rest.len() > 54 && matches!(rest[14], 12 | 40 | 52 | 56 | 108 | 124),
                "elf" => rest.len() > 6 && matches!(rest[4], 1 | 2) && matches!(rest[5], 1 | 2),
                "gzip" => rest.len() > 10 && rest[3] < 0x20,
                "zip" => {
                    let ok = first_zip;
                    first_zip = false;
                    ok
                }
                // A short 2-byte zlib header is everywhere; keep it only if it really inflates.
                "zlib" => containers::decompress("zlib", rest, 64).map(|(_, d)| d.len() >= 16).unwrap_or(false),
                "xz" | "zstd" => true,
                _ => true,
            };
            if valid {
                found.push((off, k));
            }
            if found.len() >= MAX_CARVES * 2 {
                break;
            }
        }
    }
    found.sort();
    found.dedup_by_key(|f| f.0);
    for (off, k) in found.into_iter().take(MAX_CARVES) {
        let rest = &data[off..];
        // Compressed streams: hand over the decompressed content, not a copy of the remainder.
        if matches!(k, "gzip" | "zlib" | "bzip2" | "xz" | "zstd") {
            if let Some((label, out)) = containers::decompress(k, rest, limit) {
                kids.push(Child::new(format!("carved {k} @0x{off:x} -> {label}"), out).artifact());
            }
            continue;
        }
        let end = match k {
            "png" => png_end(rest),
            "bmp" => {
                let s = u32::from_le_bytes(rest[2..6].try_into().unwrap()) as usize;
                if s > 54 && s <= rest.len() { s } else { rest.len() }
            }
            "wav" => (u32::from_le_bytes(rest[4..8].try_into().unwrap()) as usize + 8).min(rest.len()),
            _ => rest.len(),
        };
        kids.push(Child::new(format!("carved {k} @0x{off:x}"), rest[..end].to_vec()).artifact());
    }
}

fn png_end(d: &[u8]) -> usize {
    let mut pos = 8;
    while pos + 12 <= d.len() {
        let len = u32::from_be_bytes(d[pos..pos + 4].try_into().unwrap()) as usize;
        let ty = &d[pos + 4..pos + 8];
        pos = pos.saturating_add(12 + len);
        if ty == b"IEND" || pos > d.len() {
            break;
        }
    }
    pos.min(d.len())
}
