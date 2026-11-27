//! Byte-wise ciphers: XOR (single and short repeating key), Caesar/ROT-N, ROT47, Atbash.
//!
//! When the flag format has a literal prefix (`flag{`), these use known-plaintext search: one
//! linear pass derives the key at each position from the prefix and verifies the rest, so even big
//! files are cheap. Custom regexes without a literal prefix fall back to brute force on small nodes.

use super::{Child, util};
use crate::config::FlagMatcher;
use memchr::memmem;
use std::collections::HashSet;

pub struct Hit {
    pub transform: String,
    pub flag: String,
    pub offset: usize,
}

const WINDOW: usize = 320;
const BRUTE_LIMIT: usize = 256 * 1024;

pub fn rot13(d: &[u8]) -> Vec<u8> {
    d.iter().map(|&b| rot_letter(b, 13)).collect()
}

fn rot_letter(b: u8, n: u8) -> u8 {
    match b {
        b'a'..=b'z' => b'a' + (b - b'a' + n) % 26,
        b'A'..=b'Z' => b'A' + (b - b'A' + n) % 26,
        _ => b,
    }
}

fn rot47(b: u8) -> u8 {
    if (33..=126).contains(&b) { 33 + (b - 33 + 47) % 94 } else { b }
}

fn atbash(b: u8) -> u8 {
    match b {
        b'a'..=b'z' => b'z' - (b - b'a'),
        b'A'..=b'Z' => b'Z' - (b - b'A'),
        _ => b,
    }
}

fn letter_idx(b: u8) -> Option<u8> {
    match b {
        b'a'..=b'z' => Some(b - b'a'),
        b'A'..=b'Z' => Some(b - b'A'),
        _ => None,
    }
}

struct Collector<'a> {
    data: &'a [u8],
    m: &'a FlagMatcher,
    hits: Vec<Hit>,
    seen: HashSet<(String, String)>,
}

impl Collector<'_> {
    fn try_window(&mut self, at: usize, transform: impl FnOnce() -> String, decode: impl Fn(usize, u8) -> u8) {
        let end = (at + WINDOW).min(self.data.len());
        let window: Vec<u8> = self.data[at..end].iter().enumerate().map(|(j, &b)| decode(j, b)).collect();
        let Some(flag) = self.m.match_at_start(&window) else { return };
        if !plausible(&flag) {
            return;
        }
        // Ignore "decodings" that are the plain flag with its case flipped (e.g. XOR 0x20).
        let raw = &self.data[at..(at + flag.len()).min(self.data.len())];
        if raw.eq_ignore_ascii_case(flag.as_bytes()) {
            return;
        }
        let t = transform();
        if self.seen.insert((t.clone(), flag.clone())) {
            self.hits.push(Hit { transform: t, flag, offset: at });
        }
    }
}

pub fn scan(data: &[u8], m: &FlagMatcher, xor: bool, rot: bool) -> Vec<Hit> {
    let mut c = Collector { data, m, hits: vec![], seen: HashSet::new() };
    let n = data.len();
    for p in &m.prefixes {
        let l = p.len();
        if l < 3 || n < l {
            continue;
        }
        if xor {
            // Single-byte XOR.
            for i in 0..=n - l {
                let k = data[i] ^ p[0];
                if k == 0 || data[i + 1] ^ k != p[1] || data[i + 2] ^ k != p[2] {
                    continue;
                }
                if (3..l).all(|j| data[i + j] ^ k == p[j]) {
                    c.try_window(i, || format!("xor 0x{k:02x}"), |_, b| b ^ k);
                }
            }
            // Repeating-key XOR with key length 2..=l-3 (at least three verification bytes).
            for klen in 2..=(l.saturating_sub(3)).min(8) {
                for i in 0..=n - l {
                    if data[i + klen] ^ p[klen] != data[i] ^ p[0] {
                        continue;
                    }
                    let ks: Vec<u8> = (0..l).map(|j| data[i + j] ^ p[j]).collect();
                    if !(klen..l).all(|j| ks[j] == ks[j - klen]) || ks[..klen].iter().all(|&x| x == ks[0]) {
                        continue;
                    }
                    let key = ks[..klen].to_vec();
                    // Express the key in phase with the start of this blob.
                    let mut phased = vec![0u8; klen];
                    for t in 0..klen {
                        phased[(i + t) % klen] = key[t];
                    }
                    c.try_window(
                        i,
                        || format!("xor key {} (repeating)", hex(&phased)),
                        |j, b| b ^ key[j % klen],
                    );
                }
            }
        }
        if rot {
            // Caesar / ROT-N on letters, anchored on the first letter of the prefix.
            if let Some(a) = p.iter().position(|b| b.is_ascii_alphabetic()) {
                let pa = letter_idx(p[a]).unwrap();
                for i in 0..=n - l {
                    let Some(da) = letter_idx(data[i + a]) else { continue };
                    let shift = (da + 26 - pa) % 26;
                    if shift == 0 {
                        continue;
                    }
                    let ok = (0..l).all(|j| match letter_idx(p[j]) {
                        Some(pj) => {
                            letter_idx(data[i + j]).map(|dj| (dj + 26 - pj) % 26 == shift).unwrap_or(false)
                                && data[i + j].is_ascii_uppercase() == p[j].is_ascii_uppercase()
                        }
                        None => data[i + j] == p[j],
                    });
                    if ok {
                        c.try_window(i, || format!("caesar shift {shift} (decode ROT{})", 26 - shift), |_, b| rot_letter(b, 26 - shift));
                    }
                }
            }
            for (name, f) in [("rot47", rot47 as fn(u8) -> u8), ("atbash", atbash as fn(u8) -> u8)] {
                let needle: Vec<u8> = p.iter().map(|&b| f(b)).collect();
                if needle == *p {
                    continue;
                }
                for i in memmem::find_iter(data, &needle).collect::<Vec<_>>() {
                    c.try_window(i, || name.to_string(), |_, b| f(b));
                }
            }
        }
    }

    if m.has_nonliteral && n <= BRUTE_LIMIT {
        let mut brute = |label: String, f: &dyn Fn(u8) -> u8| {
            let mapped: Vec<u8> = data.iter().map(|&b| f(b)).collect();
            for (off, flag) in m.find_all(&mapped) {
                if !plausible(&flag) {
                    continue;
                }
                let raw = &data[off..off + flag.len()];
                if raw.eq_ignore_ascii_case(flag.as_bytes()) {
                    continue;
                }
                if c.seen.insert((label.clone(), flag.clone())) {
                    c.hits.push(Hit { transform: label.clone(), flag, offset: off });
                }
            }
        };
        if xor && !m.generic {
            for k in 1..=255u8 {
                brute(format!("xor 0x{k:02x}"), &|b| b ^ k);
            }
        }
        if rot {
            for s in 1..26u8 {
                brute(format!("caesar shift {} (decode ROT{s})", 26 - s), &|b| rot_letter(b, s));
            }
            brute("rot47".into(), &rot47);
            brute("atbash".into(), &atbash);
        }
    }
    c.hits
}

/// Guard against coincidences in cipher brute force: the flag body must look like a real flag.
fn plausible(flag: &str) -> bool {
    let Some(open) = flag.find('{') else { return true };
    let body = &flag[open + 1..flag.len().saturating_sub(1)];
    let good = body.chars().filter(|c| c.is_ascii_alphanumeric() || "_-!?.@$#+ ".contains(*c)).count();
    body.len() >= 4 && good * 100 >= body.len() * 85
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const MAGICS: &[(&str, &[u8])] = &[
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("zip", b"PK\x03\x04\x14\x00\x00\x00"),
    ("zip", b"PK\x03\x04\x14\x00\x08\x00"),
    ("zip", b"PK\x03\x04\x0a\x00\x00\x00"),
    ("zip", b"PK\x03\x04"),
    ("pdf", b"%PDF-1."),
    ("gzip", b"\x1f\x8b\x08"),
    ("jpeg", b"\xff\xd8\xff\xe0\x00\x10JFIF"),
    ("jpeg", b"\xff\xd8\xff\xe1"),
    ("gif", b"GIF89a"),
    ("gif", b"GIF87a"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("elf", b"\x7fELF\x02\x01\x01"),
    ("bzip2", b"BZh91AY&SY"),
    ("rar", b"Rar!\x1a\x07"),
];

/// Whole-blob XOR where the result starts with a known file header (e.g. a PNG XORed with 0x42
/// or with a short repeating key). Produces decrypted children.
pub fn xor_magic_children(data: &[u8], kind: Option<&str>, kids: &mut Vec<Child>) {
    if kind.is_some() || data.len() < 16 {
        return;
    }
    let mut done = HashSet::new();
    for (name, magic) in MAGICS {
        let l = magic.len();
        let ks: Vec<u8> = (0..l).map(|j| data[j] ^ magic[j]).collect();
        for klen in 1..=(l / 2).min(6) {
            if !(klen..l).all(|j| ks[j] == ks[j - klen]) {
                continue;
            }
            let key = &ks[..klen];
            if key.iter().all(|&k| k == 0) || !done.insert(key.to_vec()) {
                break;
            }
            let out: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ key[i % klen]).collect();
            if util::sniff(&out).is_some() {
                let mut c = Child::new(format!("xor key {} -> {name}", hex(key)), out).artifact();
                c.origin.xored = true;
                kids.push(c);
            }
            break;
        }
    }
}
