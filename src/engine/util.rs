use std::io::Read;

/// Identify common file types by magic bytes at offset 0.
pub fn sniff(d: &[u8]) -> Option<&'static str> {
    let s = |m: &[u8]| d.starts_with(m);
    Some(if s(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else if s(b"\xff\xd8\xff") {
        "jpeg"
    } else if s(b"GIF87a") || s(b"GIF89a") {
        "gif"
    } else if s(b"BM") && d.len() > 26 && u32::from_le_bytes(d[2..6].try_into().unwrap()) as usize <= d.len() + 16 && d[6..10] == [0; 4] {
        "bmp"
    } else if s(b"II*\0") || s(b"MM\0*") {
        "tiff"
    } else if s(b"RIFF") && d.len() > 12 && &d[8..12] == b"WEBP" {
        "webp"
    } else if s(b"RIFF") && d.len() > 12 && &d[8..12] == b"WAVE" {
        "wav"
    } else if s(b"%PDF-") {
        "pdf"
    } else if s(b"PK\x03\x04") || s(b"PK\x05\x06") {
        "zip"
    } else if s(b"\x1f\x8b") {
        "gzip"
    } else if d.len() > 10 && s(b"BZh") && (b'1'..=b'9').contains(&d[3]) {
        "bzip2"
    } else if s(b"\xfd7zXZ\0") {
        "xz"
    } else if s(b"7z\xbc\xaf\x27\x1c") {
        "7z"
    } else if s(b"\x28\xb5\x2f\xfd") {
        "zstd"
    } else if s(b"Rar!\x1a\x07") {
        "rar"
    } else if d.len() > 262 && &d[257..262] == b"ustar" {
        "tar"
    } else if s(b"\xd4\xc3\xb2\xa1") || s(b"\xa1\xb2\xc3\xd4") || s(b"\x4d\x3c\xb2\xa1") || s(b"\xa1\xb2\x3c\x4d") {
        "pcap"
    } else if s(b"\x0a\x0d\x0d\x0a") {
        "pcapng"
    } else if s(b"\x7fELF") {
        "elf"
    } else if s(b"MZ") {
        "pe"
    } else if d.len() > 2 && d[0] == 0x78 && matches!(d[1], 0x01 | 0x5e | 0x9c | 0xda) {
        "zlib"
    } else if d.len() > 13 && d[0] == 0x5d && d[1] == 0 && d[2] == 0 {
        "lzma"
    } else if s(b"OggS") {
        "ogg"
    } else if s(b"ID3") || s(b"fLaC") {
        "audio"
    } else {
        return None;
    })
}

pub fn ext_for(kind: &str) -> &'static str {
    match kind {
        "png" => "png",
        "jpeg" => "jpg",
        "gif" => "gif",
        "bmp" => "bmp",
        "tiff" => "tif",
        "webp" => "webp",
        "wav" => "wav",
        "pdf" => "pdf",
        "zip" => "zip",
        "gzip" => "gz",
        "bzip2" => "bz2",
        "xz" => "xz",
        "7z" => "7z",
        "zstd" => "zst",
        "rar" => "rar",
        "tar" => "tar",
        "pcap" => "pcap",
        "pcapng" => "pcapng",
        "elf" => "elf",
        "pe" => "exe",
        "zlib" => "zlib",
        "lzma" => "lzma",
        "ogg" => "ogg",
        _ => "bin",
    }
}

/// Fraction of bytes that are printable ASCII or common whitespace (first 64 KiB).
pub fn printable_ratio(d: &[u8]) -> f64 {
    let d = &d[..d.len().min(65536)];
    if d.is_empty() {
        return 0.0;
    }
    let n = d.iter().filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t').count();
    n as f64 / d.len() as f64
}

/// Decoded output worth recursing into: readable text, or a recognisable file.
pub fn interesting(d: &[u8]) -> bool {
    d.len() >= 4 && (printable_ratio(d) >= 0.9 || sniff(d).is_some())
}

/// Read up to `limit` bytes; keep whatever was produced before an error (truncated streams are
/// common in CTF files).
pub fn read_limited(r: impl Read, limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut r = r.take(limit as u64);
    let mut buf = [0u8; 65536];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn sanitize_name(label: &str, data: &[u8]) -> String {
    let label = label.split(" (").next().unwrap_or(label);
    let label = label.rsplit(['/', ':']).next().unwrap_or(label);
    let mut s: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    s = s.trim_matches('_').to_string();
    s.truncate(80);
    if s.is_empty() {
        s = "artifact".into();
    }
    if !s.contains('.') {
        if let Some(k) = sniff(data) {
            s.push('.');
            s.push_str(ext_for(k));
        } else if printable_ratio(data) > 0.9 {
            s.push_str(".txt");
        } else {
            s.push_str(".bin");
        }
    }
    s
}

pub fn preview(d: &[u8], n: usize) -> String {
    d.iter()
        .take(n)
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}
