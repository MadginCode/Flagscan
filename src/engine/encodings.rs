//! Text encodings found anywhere inside a blob: base64/32/58/85, hex (several styles), binary,
//! decimal bytes, URL / HTML escapes, Morse, and UTF-16 strings.

use super::{Child, Origin, util};
use base64::Engine;
use regex::bytes::Regex;
use std::sync::LazyLock;

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

re!(B64, r"[A-Za-z0-9+/]{12,}={0,2}");
re!(B64URL, r"[A-Za-z0-9_\-]{12,}={0,2}");
re!(B32, r"[A-Z2-7]{16,}={0,6}");
re!(B58, r"[1-9A-HJ-NP-Za-km-z]{12,}");
re!(A85, r"(?s)<~(.{4,}?)~>");
re!(HEX, r"(?:[0-9a-fA-F]{2}){6,}");
re!(HEXSEP, r"[0-9a-fA-F]{2}(?:[ :,\-][0-9a-fA-F]{2}){5,}");
re!(HEXESC, r"(?:(?:\\x|0x|%)[0-9a-fA-F]{2}[ ,]*){4,}");
re!(BIN, r"(?:[01]{8}[ ,]?){3,}");
re!(DEC, r"\b(?:\d{1,3}[ ,;]+){4,}\d{1,3}\b");
re!(OCT, r"(?:\\[0-7]{3}){4,}");
re!(PCT, r"%[0-9a-fA-F]{2}");
re!(HTMLENT, r"&#(?:x[0-9a-fA-F]+|[0-9]+);");
re!(MORSE, r"(?:[.\-]{1,7}(?:[ ]+|[ ]*[/|][ ]*)){3,}[.\-]{1,7}");

const MAX_RUNS: usize = 200;

fn push(kids: &mut Vec<Child>, label: String, data: Vec<u8>) {
    if util::interesting(&data) {
        kids.push(Child::new(label, data));
    }
}

pub fn expand(data: &[u8], kids: &mut Vec<Child>) {
    let texty = util::printable_ratio(data) > 0.6;

    // base64 (standard and url-safe), decoded run by run.
    for (re, name, std) in [(&*B64, "base64", true), (&*B64URL, "base64url", false)] {
        for m in re.find_iter(data).take(MAX_RUNS) {
            let s = m.as_bytes();
            if !std && !s.iter().any(|&b| b == b'-' || b == b'_') {
                continue;
            }
            if let Some(d) = b64(s, std) {
                push(kids, format!("{name}@0x{:x}", m.start()), d);
            }
        }
    }
    for m in B32.find_iter(data).take(MAX_RUNS) {
        if let Some(d) = b32(m.as_bytes()) {
            push(kids, format!("base32@0x{:x}", m.start()), d);
        }
    }
    for m in B58.find_iter(data).take(MAX_RUNS) {
        let s = m.as_bytes();
        // Only bother when it cannot be plain base64-of-something-else or ordinary words.
        if s.len() <= 1024 && s.iter().any(|b| b.is_ascii_digit()) && s.iter().any(|b| b.is_ascii_uppercase())
            && let Some(d) = b58(s) {
                push(kids, format!("base58@0x{:x}", m.start()), d);
            }
    }
    for c in A85.captures_iter(data).take(MAX_RUNS) {
        let g = c.get(1).unwrap();
        if let Some(d) = a85(g.as_bytes()) {
            push(kids, format!("ascii85@0x{:x}", g.start()), d);
        }
    }
    for re in [&*HEX, &*HEXSEP, &*HEXESC] {
        for m in re.find_iter(data).take(MAX_RUNS) {
            if let Some(d) = hex_loose(m.as_bytes()) {
                push(kids, format!("hex@0x{:x}", m.start()), d);
            }
        }
    }
    for m in BIN.find_iter(data).take(MAX_RUNS) {
        let bits: Vec<u8> = m.as_bytes().iter().filter(|b| matches!(b, b'0' | b'1')).copied().collect();
        let d: Vec<u8> = bits.chunks_exact(8).map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | (b - b'0'))).collect();
        push(kids, format!("binary@0x{:x}", m.start()), d);
    }
    if texty {
        for m in DEC.find_iter(data).take(MAX_RUNS) {
            let nums: Option<Vec<u8>> = std::str::from_utf8(m.as_bytes())
                .ok()
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).map(|x| x.parse::<u16>().ok().filter(|&v| v < 256).map(|v| v as u8)).collect());
            if let Some(d) = nums {
                push(kids, format!("decimal@0x{:x}", m.start()), d);
            }
        }
        for m in OCT.find_iter(data).take(MAX_RUNS) {
            let d: Vec<u8> = m
                .as_bytes()
                .split(|&b| b == b'\\')
                .filter(|x| x.len() == 3)
                .filter_map(|x| u8::from_str_radix(std::str::from_utf8(x).ok()?, 8).ok())
                .collect();
            push(kids, format!("octal@0x{:x}", m.start()), d);
        }
        if PCT.find_iter(data).take(3).count() == 3 {
            let d: Vec<u8> = percent_encoding::percent_decode(data).collect();
            let d: Vec<u8> = d.iter().map(|&b| if b == b'+' { b' ' } else { b }).collect();
            push(kids, "url-decode".into(), d);
        }
        if HTMLENT.find_iter(data).take(3).count() == 3 {
            push(kids, "html-entities".into(), html_entities(data));
        }
        for m in MORSE.find_iter(data).take(MAX_RUNS) {
            if let Some(d) = morse(m.as_bytes()) {
                push(kids, format!("morse@0x{:x}", m.start()), d);
            }
        }
        // Whole blob that is base64/base32/hex wrapped over several lines.
        let compact: Vec<u8> = data.iter().filter(|b| !b.is_ascii_whitespace()).copied().collect();
        if compact.len() >= 16 && compact.len() < data.len() {
            if compact.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                && let Some(d) = b64(&compact, true) {
                    push(kids, "base64 (multi-line)".into(), d);
                }
            if compact.iter().all(|b| b.is_ascii_hexdigit())
                && let Some(d) = hex_loose(&compact) {
                    push(kids, "hex (multi-line)".into(), d);
                }
        }
    }

    // UTF-16 strings (Windows artefacts, memory dumps, registry...).
    for (be, name) in [(false, "utf16le strings"), (true, "utf16be strings")] {
        let s = utf16_strings(data, be);
        if s.len() >= 6 {
            kids.push(Child::new(name, s).with_origin(Origin { text_only: true, ..Default::default() }));
        }
    }
}

pub fn b64(s: &[u8], standard: bool) -> Option<Vec<u8>> {
    let trimmed: Vec<u8> = s.iter().filter(|&&b| b != b'=').copied().collect();
    if trimmed.len() % 4 == 1 {
        return None;
    }
    let eng = if standard { &base64::engine::general_purpose::STANDARD_NO_PAD } else { &base64::engine::general_purpose::URL_SAFE_NO_PAD };
    let cfg = base64::engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
    let lenient = base64::engine::GeneralPurpose::new(if standard { &base64::alphabet::STANDARD } else { &base64::alphabet::URL_SAFE }, cfg);
    eng.decode(&trimmed).ok().or_else(|| lenient.decode(&trimmed).ok())
}

fn b32(s: &[u8]) -> Option<Vec<u8>> {
    let mut t: Vec<u8> = s.iter().filter(|&&b| b != b'=').copied().collect();
    while !t.len().is_multiple_of(8) {
        t.push(b'=');
    }
    data_encoding::BASE32.decode(&t).ok()
}

fn b58(s: &[u8]) -> Option<Vec<u8>> {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num: Vec<u8> = vec![]; // little-endian base256
    for &c in s {
        let mut carry = ALPHA.iter().position(|&a| a == c)? as u32;
        for d in num.iter_mut() {
            carry += *d as u32 * 58;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.iter().take_while(|&&c| c == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev());
    Some(out)
}

fn a85(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut group: Vec<u32> = Vec::with_capacity(5);
    for &c in s {
        match c {
            b'z' if group.is_empty() => out.extend_from_slice(&[0; 4]),
            b'!'..=b'u' => {
                group.push((c - 33) as u32);
                if group.len() == 5 {
                    let v = group.iter().try_fold(0u32, |a, &d| a.checked_mul(85)?.checked_add(d))?;
                    out.extend_from_slice(&v.to_be_bytes());
                    group.clear();
                }
            }
            c if c.is_ascii_whitespace() => {}
            _ => return None,
        }
    }
    if !group.is_empty() {
        let n = group.len();
        while group.len() < 5 {
            group.push(84);
        }
        let v = group.iter().try_fold(0u32, |a, &d| a.checked_mul(85)?.checked_add(d))?;
        out.extend_from_slice(&v.to_be_bytes()[..n - 1]);
    }
    Some(out)
}

fn hex_loose(s: &[u8]) -> Option<Vec<u8>> {
    let s = String::from_utf8_lossy(s).replace("0x", "").replace("\\x", "").replace('%', "");
    let digits: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    if digits.len() < 8 || !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

fn html_entities(d: &[u8]) -> Vec<u8> {
    HTMLENT
        .replace_all(d, |c: &regex::bytes::Captures| {
            let s = std::str::from_utf8(&c[0]).unwrap_or("");
            let inner = &s[2..s.len() - 1];
            let v = if let Some(h) = inner.strip_prefix('x') { u32::from_str_radix(h, 16).ok() } else { inner.parse().ok() };
            v.and_then(char::from_u32).map(|ch| ch.to_string().into_bytes()).unwrap_or_default()
        })
        .into_owned()
}

fn morse(s: &[u8]) -> Option<Vec<u8>> {
    const T: &[(&str, char)] = &[
        (".-", 'A'), ("-...", 'B'), ("-.-.", 'C'), ("-..", 'D'), (".", 'E'), ("..-.", 'F'), ("--.", 'G'),
        ("....", 'H'), ("..", 'I'), (".---", 'J'), ("-.-", 'K'), (".-..", 'L'), ("--", 'M'), ("-.", 'N'),
        ("---", 'O'), (".--.", 'P'), ("--.-", 'Q'), (".-.", 'R'), ("...", 'S'), ("-", 'T'), ("..-", 'U'),
        ("...-", 'V'), (".--", 'W'), ("-..-", 'X'), ("-.--", 'Y'), ("--..", 'Z'), ("-----", '0'),
        (".----", '1'), ("..---", '2'), ("...--", '3'), ("....-", '4'), (".....", '5'), ("-....", '6'),
        ("--...", '7'), ("---..", '8'), ("----.", '9'), (".-.-.-", '.'), ("--..--", ','), ("..--.-", '_'),
        ("-.--.", '{'), ("-.--.-", '}'), ("-....-", '-'), ("..--..", '?'), ("-.-.--", '!'),
    ];
    let s = std::str::from_utf8(s).ok()?;
    let mut out = String::new();
    for word in s.split(['/', '|']) {
        for sym in word.split_whitespace() {
            out.push(T.iter().find(|(m, _)| *m == sym)?.1);
        }
        out.push(' ');
    }
    let out = out.trim().to_string();
    (out.len() >= 3).then(|| out.into_bytes())
}

fn utf16_strings(d: &[u8], be: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i + 1 < d.len() {
        let (c, z) = if be { (d[i + 1], d[i]) } else { (d[i], d[i + 1]) };
        if z == 0 && ((0x20..0x7f).contains(&c) || c == b'\t') {
            cur.push(c);
            i += 2;
        } else {
            if cur.len() >= 5 {
                out.extend_from_slice(&cur);
                out.push(b'\n');
            }
            cur.clear();
            i += 1;
        }
    }
    if cur.len() >= 5 {
        out.extend_from_slice(&cur);
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decoders() {
        assert_eq!(b58(b"StV1DL6CwTryKyV").unwrap(), b"hello world");
        assert_eq!(a85(b"87cURD]i,\"Ebo7").unwrap(), b"Hello World");
        assert_eq!(morse(b".... .. / - .... . .-. .").unwrap(), b"HI THERE");
        assert_eq!(hex_loose(b"\\x66\\x6c\\x61\\x67").unwrap(), b"flag");
    }
}
