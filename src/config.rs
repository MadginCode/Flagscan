//! Scan configuration and the compiled flag matcher.

use anyhow::{Context, Result};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Modules {
    /// base64/32/58/85, hex, binary, decimal, URL, HTML entities, Morse, UTF-16
    pub encodings: bool,
    /// zip, tar, gzip, zlib, bzip2, xz, lzma, zstd, 7z
    pub archives: bool,
    /// EXIF, PNG chunks / CRC, JPEG comments + trailer, PDF streams, pcap flows
    pub metadata: bool,
    /// embedded files found by magic bytes
    pub carving: bool,
    /// image and WAV least-significant-bit planes
    pub stego: bool,
    /// single and short repeating-key XOR (known-plaintext on the flag prefix)
    pub xor: bool,
    /// Caesar / ROT-N, ROT47, Atbash, Vigenere, reversed text
    pub rot: bool,
    /// QR codes and barcodes in images
    pub qr: bool,
}

impl Default for Modules {
    fn default() -> Self {
        Self { encodings: true, archives: true, metadata: true, carving: true, stego: true, xor: true, rot: true, qr: true }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Flag formats such as `flag{}`, `CTF{`, `picoCTF`. The prefix is the text before `{`.
    pub formats: Vec<String>,
    /// Optional extra regex (byte regex syntax). Used in addition to `formats`.
    pub regex: String,
    /// Match the prefix case-insensitively (`FLAG{`, `Flag{` ...).
    pub case_insensitive: bool,
    /// Also report anything shaped like `word{...}` (noisy, off by default).
    pub generic: bool,
    pub max_depth: usize,
    pub max_nodes: usize,
    /// Files bigger than this (bytes) are skipped when walking folders.
    pub max_file_size: u64,
    /// Upper bound for any single decoded / decompressed blob (zip-bomb guard).
    pub max_node_size: usize,
    /// Passwords tried on encrypted zip / 7z entries (plus a built-in short list).
    pub passwords: Vec<String>,
    /// Optional path to a wordlist file (one password per line, e.g. rockyou.txt).
    pub wordlist: String,
    /// Give up on a single input file after this many milliseconds (0 = no limit).
    pub file_timeout_ms: u64,
    /// Worker threads for scanning a folder (0 = number of CPUs).
    pub threads: usize,
    pub modules: Modules,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            formats: vec!["flag{}".into()],
            regex: String::new(),
            case_insensitive: true,
            generic: false,
            max_depth: 10,
            max_nodes: 20_000,
            max_file_size: 1024 * 1024 * 1024,
            max_node_size: 128 * 1024 * 1024,
            passwords: vec![],
            wordlist: String::new(),
            file_timeout_ms: 0,
            threads: 0,
            modules: Modules::default(),
        }
    }
}

/// Cap on passwords pulled from a wordlist file, to bound crack time.
pub const MAX_WORDLIST: usize = 1_000_000;

pub const DEFAULT_PASSWORDS: &[&str] = &[
    "", "password", "infected", "flag", "ctf", "secret", "admin", "123456", "12345678", "1234",
    "letmein", "qwerty", "root", "toor", "pass", "test", "hunter2", "princess", "iloveyou",
];

impl ScanConfig {
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("flagscan").join("config.json"))
    }

    pub fn load() -> Self {
        Self::path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let p = Self::path().context("no config directory on this system")?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(p, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn all_passwords(&self) -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = self.passwords.iter().map(|p| p.as_bytes().to_vec()).collect();
        for p in &self.formats {
            let pre = split_format(p);
            if !pre.is_empty() {
                v.push(pre.as_bytes().to_vec());
                v.push(pre.to_lowercase().into_bytes());
            }
        }
        v.extend(DEFAULT_PASSWORDS.iter().map(|p| p.as_bytes().to_vec()));
        // The user-supplied list and defaults come first (fast common cases); the wordlist,
        // which can be huge, is appended and tried only if those miss.
        if !self.wordlist.trim().is_empty() {
            match std::fs::File::open(self.wordlist.trim()) {
                Ok(f) => {
                    use std::io::BufRead;
                    for line in std::io::BufReader::new(f).lines().map_while(Result::ok).take(MAX_WORDLIST) {
                        let w = line.trim_end_matches(['\r', '\n']);
                        if !w.is_empty() {
                            v.push(w.as_bytes().to_vec());
                        }
                    }
                }
                Err(e) => eprintln!("wordlist {}: {e}", self.wordlist.trim()),
            }
        }
        // Dedup while preserving order (passwords are tried in order).
        let mut seen = std::collections::HashSet::new();
        v.retain(|p| seen.insert(p.clone()));
        v
    }
}

/// `flag{}` / `flag{` / `flag{...}` / `flag` -> `flag`
pub fn split_format(f: &str) -> String {
    let f = f.trim();
    match f.find('{') {
        Some(i) => f[..i].to_string(),
        None => f.to_string(),
    }
}

fn regex_literal_prefix(re: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut it = re.chars().peekable();
    while let Some(&c) = it.peek() {
        if c == '\\' {
            it.next();
            match it.next() {
                Some(n) if n.is_ascii_punctuation() => out.push(n as u8),
                _ => break,
            }
        } else if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            it.next();
            out.push(c as u8);
        } else {
            // A quantifier would make the last literal optional or repeated.
            if matches!(c, '?' | '*' | '{') {
                out.pop();
            }
            break;
        }
    }
    out
}

/// Compiled flag matcher.
pub struct FlagMatcher {
    pub regex: Regex,
    /// Same without the generic `word{...}` alternative; used on reversed / rotated text where
    /// generic matching would only produce noise. None if generic is the only pattern.
    pub strict: Option<Regex>,
    /// Literal prefixes including the opening brace, in the case variants worth trying
    /// (as typed, lower, upper, capitalised). Used for XOR / ROT known-plaintext search.
    pub prefixes: Vec<Vec<u8>>,
    /// True when some pattern has no literal prefix (custom regex / generic mode),
    /// which forces brute-force transforms on small nodes.
    pub has_nonliteral: bool,
    /// Generic `word{...}` matching is on: brute-forcing XOR would just produce noise.
    pub generic: bool,
}

const BODY: &str = r"(?-u:[\x20-\x7a\x7c\x7e]){1,300}\}";

impl FlagMatcher {
    pub fn new(cfg: &ScanConfig) -> Result<Self> {
        let mut alts = Vec::new();
        let mut prefixes: Vec<Vec<u8>> = Vec::new();
        for f in &cfg.formats {
            let pre = split_format(f);
            if pre.is_empty() {
                continue;
            }
            let esc = regex::escape(&pre);
            if cfg.case_insensitive {
                alts.push(format!(r"(?i:{esc})\{{{BODY}"));
            } else {
                alts.push(format!(r"{esc}\{{{BODY}"));
            }
            let mut variants = vec![pre.clone()];
            if cfg.case_insensitive {
                variants.push(pre.to_lowercase());
                variants.push(pre.to_uppercase());
                let mut c = pre.to_lowercase();
                if let Some(first) = c.get(0..1) {
                    c = first.to_uppercase() + &c[1..];
                }
                variants.push(c);
            }
            for v in variants {
                let mut b = v.into_bytes();
                b.push(b'{');
                if !prefixes.contains(&b) {
                    prefixes.push(b);
                }
            }
        }
        let mut has_nonliteral = false;
        if !cfg.regex.trim().is_empty() {
            Regex::new(cfg.regex.trim()).context("invalid custom regex")?;
            alts.push(format!("(?:{})", cfg.regex.trim()));
            has_nonliteral = true;
            // Leading literal of the regex (e.g. `HTB\{` in `HTB\{[a-z]+\}`) enables the fast
            // known-plaintext XOR / ROT search for it too.
            let lit = regex_literal_prefix(cfg.regex.trim());
            if lit.len() >= 3 && !prefixes.contains(&lit) {
                prefixes.push(lit);
            }
        }
        let strict = if alts.is_empty() { None } else { Some(Regex::new(&alts.join("|")).context("building flag regex")?) };
        if cfg.generic {
            alts.push(r"\b[A-Za-z][A-Za-z0-9_\-]{1,24}\{(?-u:[\x20-\x7a\x7c\x7e]){4,200}\}".to_string());
        }
        if alts.is_empty() {
            anyhow::bail!("no flag format configured");
        }
        let regex = Regex::new(&alts.join("|")).context("building flag regex")?;
        Ok(Self { regex, strict, prefixes, has_nonliteral, generic: cfg.generic })
    }

    /// Returns (offset, flag) for every match.
    pub fn find_all(&self, data: &[u8]) -> Vec<(usize, String)> {
        self.regex
            .find_iter(data)
            .map(|m| (m.start(), String::from_utf8_lossy(m.as_bytes()).into_owned()))
            .collect()
    }

    pub fn find_all_strict(&self, data: &[u8]) -> Vec<(usize, String)> {
        let Some(re) = &self.strict else { return vec![] };
        re.find_iter(data).map(|m| (m.start(), String::from_utf8_lossy(m.as_bytes()).into_owned())).collect()
    }

    /// Match that starts exactly at the beginning of `window`.
    pub fn match_at_start(&self, window: &[u8]) -> Option<String> {
        let m = self.regex.find(window)?;
        (m.start() == 0).then(|| String::from_utf8_lossy(m.as_bytes()).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_basics() {
        let cfg = ScanConfig { formats: vec!["picoCTF{}".into()], ..Default::default() };
        let m = FlagMatcher::new(&cfg).unwrap();
        assert_eq!(m.find_all(b"xx PICOCTF{a_b} yy")[0].1, "PICOCTF{a_b}");
        assert!(m.find_all(b"picoCTF{\x01}").is_empty());
        assert!(m.prefixes.contains(&b"picoCTF{".to_vec()));
        assert_eq!(regex_literal_prefix(r"HTB\{[a-z]+\}"), b"HTB{");
        assert_eq!(regex_literal_prefix(r"abc?d"), b"ab");
    }
}
