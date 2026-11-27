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
re!(B45, r"[0-9A-Z $%*+\-./:]{9,}");
re!(B62, r"[0-9A-Za-z]{16,}");
re!(UUE, r"(?s)begin[ \t]+[0-7]{3}[ \t]+\S.*?\nend");
re!(QP, r"=[0-9A-F]{2}");
re!(BACON, r"(?i)(?:[ab]{5}[^a-z]*){4,}");
re!(BF, r"[-+<>.,\[\]]{20,}");
re!(OOK, r"(?:Ook[.?!][ \t]*){6,}");

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
        for m in B45.find_iter(data).take(MAX_RUNS) {
            if let Some(d) = b45(m.as_bytes()) {
                push(kids, format!("base45@0x{:x}", m.start()), d);
            }
        }
        for m in B62.find_iter(data).take(MAX_RUNS) {
            let s = m.as_bytes();
            // Skip runs that are already covered by base64/hex to cut noise.
            if s.len() <= 1024 && s.iter().any(|b| b.is_ascii_lowercase()) && s.iter().any(|b| b.is_ascii_uppercase())
                && let Some(d) = b62(s) {
                    push(kids, format!("base62@0x{:x}", m.start()), d);
                }
        }
        for m in BACON.find_iter(data).take(MAX_RUNS) {
            if let Some(d) = bacon(m.as_bytes()) {
                push(kids, format!("bacon@0x{:x}", m.start()), d);
            }
        }
        for m in BF.find_iter(data).take(MAX_RUNS) {
            if let Some(d) = brainfuck(m.as_bytes()) {
                push(kids, format!("brainfuck@0x{:x}", m.start()), d);
            }
        }
        for m in OOK.find_iter(data).take(MAX_RUNS) {
            if let Some(bf) = ook_to_bf(m.as_bytes())
                && let Some(d) = brainfuck(&bf) {
                    push(kids, format!("ook@0x{:x}", m.start()), d);
                }
        }
        if QP.find_iter(data).take(2).count() == 2 {
            push(kids, "quoted-printable".into(), quoted_printable(data));
        }
        for m in UUE.find_iter(data).take(16) {
            if let Some(d) = uudecode(m.as_bytes()) {
                push(kids, format!("uudecode@0x{:x}", m.start()), d);
            }
        }
        // base91 over the whole blob (it has no reliable run shape).
        if data.len() < 256 * 1024
            && let Some(d) = b91(data) {
                push(kids, "base91".into(), d);
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

/// base45 (RFC 9285): 3 chars -> 2 bytes, 2 chars -> 1 byte, little-endian within each group.
fn b45(s: &[u8]) -> Option<Vec<u8>> {
    const A: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let v: Vec<u16> = s.iter().filter(|b| !b.is_ascii_whitespace()).map(|&b| A.iter().position(|&a| a == b).map(|p| p as u16)).collect::<Option<_>>()?;
    let mut out = Vec::new();
    for c in v.chunks(3) {
        match c {
            [a, b, d] => {
                let n = *a as u32 + *b as u32 * 45 + *d as u32 * 45 * 45;
                if n > 0xffff {
                    return None;
                }
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            [a, b] => {
                let n = *a as u32 + *b as u32 * 45;
                if n > 0xff {
                    return None;
                }
                out.push(n as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// base62 as a big-endian base-62 integer (same scheme as base58).
fn b62(s: &[u8]) -> Option<Vec<u8>> {
    const A: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut num: Vec<u8> = vec![];
    for &c in s {
        let mut carry = A.iter().position(|&a| a == c)? as u32;
        for d in num.iter_mut() {
            carry += *d as u32 * 62;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.iter().take_while(|&&c| c == b'0').count();
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev());
    Some(out)
}

/// basE91 (Joachim Henke's reference scheme).
fn b91(s: &[u8]) -> Option<Vec<u8>> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
    let mut out = Vec::new();
    let (mut v, mut b, mut n): (i32, u32, u32) = (-1, 0, 0);
    let mut seen = 0usize;
    for &ch in s {
        let Some(d) = A.iter().position(|&a| a == ch) else { continue };
        seen += 1;
        let d = d as i32;
        if v < 0 {
            v = d;
        } else {
            v += d * 91;
            b |= (v as u32) << n;
            n += if (v & 8191) > 88 { 13 } else { 14 };
            while n >= 8 {
                out.push((b & 0xff) as u8);
                b >>= 8;
                n -= 8;
            }
            v = -1;
        }
    }
    if v >= 0 {
        out.push(((b | (v as u32) << n) & 0xff) as u8);
    }
    // Require it to have consumed a credible run of alphabet characters.
    (seen >= 8 && out.len() >= 4).then_some(out)
}

/// uudecode a `begin ... end` block.
fn uudecode(block: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(block).ok()?;
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        if line.trim_end() == "end" {
            break;
        }
        let bytes = line.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        let n = ((bytes[0].wrapping_sub(0x20)) & 0x3f) as usize;
        if n == 0 {
            continue;
        }
        let dec: Vec<u8> = bytes[1..].iter().map(|&c| c.wrapping_sub(0x20) & 0x3f).collect();
        let mut line = Vec::new();
        for g in dec.chunks(4) {
            if g.len() < 2 {
                break;
            }
            line.push((g[0] << 2) | (g[1] >> 4));
            if g.len() >= 3 {
                line.push((g[1] << 4) | (g[2] >> 2));
            }
            if g.len() >= 4 {
                line.push((g[2] << 6) | g[3]);
            }
        }
        line.truncate(n); // the length byte is authoritative; drop padding
        out.extend_from_slice(&line);
    }
    (!out.is_empty()).then_some(out)
}

fn quoted_printable(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < d.len() {
        if d[i] == b'=' && i + 2 < d.len() {
            if d[i + 1] == b'\r' && d[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if d[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if let Ok(s) = std::str::from_utf8(&d[i + 1..i + 3])
                && let Ok(b) = u8::from_str_radix(s, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
        }
        out.push(d[i]);
        i += 1;
    }
    out
}

/// Bacon cipher: groups of five A/B letters. Tries both the 24- and 26-letter variants.
fn bacon(s: &[u8]) -> Option<Vec<u8>> {
    let bits: Vec<u8> = s.iter().filter(|b| matches!(b, b'a' | b'b' | b'A' | b'B')).map(|&b| u8::from(matches!(b, b'b' | b'B'))).collect();
    if bits.len() < 20 {
        return None;
    }
    let decode = |full: bool| -> String {
        bits.chunks_exact(5).map(|g| {
            let v = g.iter().fold(0u8, |a, &b| (a << 1) | b) as usize;
            if full {
                (b'A' + v as u8) as char
            } else {
                // 24-letter: I/J share 8, U/V share 20.
                let idx = if v < 8 { v } else if v < 20 { v + 1 } else { v + 2 };
                (b'A' + idx.min(25) as u8) as char
            }
        }).collect()
    };
    // Prefer whichever reads as a wordy string; default to the 26-letter form.
    let full = decode(true);
    let alt = decode(false);
    Some(if looks_wordy(&alt) && !looks_wordy(&full) { alt.into_bytes() } else { full.into_bytes() })
}

fn looks_wordy(s: &str) -> bool {
    !s.is_empty() && s.bytes().filter(|b| b.is_ascii_alphanumeric()).count() * 100 >= s.len() * 90
}

/// A small, bounded Brainfuck interpreter. Returns program output.
fn brainfuck(src: &[u8]) -> Option<Vec<u8>> {
    let prog: Vec<u8> = src.iter().filter(|b| b"+-<>.,[]".contains(b)).copied().collect();
    if prog.len() < 20 {
        return None;
    }
    // Precompute bracket jumps; unbalanced brackets mean this isn't real Brainfuck.
    let mut jump = vec![0usize; prog.len()];
    let mut stack = Vec::new();
    for (i, &c) in prog.iter().enumerate() {
        if c == b'[' {
            stack.push(i);
        } else if c == b']' {
            let o = stack.pop()?;
            jump[o] = i;
            jump[i] = o;
        }
    }
    if !stack.is_empty() {
        return None;
    }
    let mut tape = vec![0u8; 30000];
    let (mut ptr, mut pc, mut steps) = (0usize, 0usize, 0u64);
    let mut out = Vec::new();
    while pc < prog.len() {
        steps += 1;
        if steps > 5_000_000 || out.len() > 1 << 20 {
            break;
        }
        match prog[pc] {
            b'+' => tape[ptr] = tape[ptr].wrapping_add(1),
            b'-' => tape[ptr] = tape[ptr].wrapping_sub(1),
            b'>' => ptr = (ptr + 1) % tape.len(),
            b'<' => ptr = (ptr + tape.len() - 1) % tape.len(),
            b'.' => out.push(tape[ptr]),
            b',' => tape[ptr] = 0,
            b'[' if tape[ptr] == 0 => pc = jump[pc],
            b']' if tape[ptr] != 0 => pc = jump[pc],
            _ => {}
        }
        pc += 1;
    }
    (!out.is_empty()).then_some(out)
}

fn ook_to_bf(s: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(s).ok()?;
    let toks: Vec<&str> = text.split_whitespace().filter(|t| t.starts_with("Ook")).collect();
    let mut out = Vec::new();
    for pair in toks.chunks_exact(2) {
        let p = (pair[0].trim_start_matches("Ook"), pair[1].trim_start_matches("Ook"));
        out.push(match p {
            (".", "?") => b'>',
            ("?", ".") => b'<',
            (".", ".") => b'+',
            ("!", "!") => b'-',
            ("!", ".") => b'.',
            (".", "!") => b',',
            ("!", "?") => b'[',
            ("?", "!") => b']',
            _ => return None,
        });
    }
    (!out.is_empty()).then_some(out)
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

    #[test]
    fn new_decoders() {
        assert_eq!(b45(b"QED8WEX0").unwrap(), b"ietf!");
        assert_eq!(b62(b"8nCDq36gw9t").unwrap(), b"flag{62}");
        assert_eq!(b91(b"@iH<,{@GBW").unwrap(), b"flag{91}");
        assert_eq!(quoted_printable(b"fl=61g=7Bqp=7D"), b"flag{qp}");
        // "HELLO" as 26-letter Bacon.
        assert_eq!(bacon(b"AABBB AABAA ABABB ABABB ABBBA").unwrap(), b"HELLO");
        // Brainfuck that prints "A".
        assert_eq!(brainfuck(b"++++++[>++++++++++<-]>+++++.").unwrap(), b"A");
        assert!(uudecode(b"begin 644 f.txt\n#9FQA\n`\nend").unwrap().starts_with(b"fla"));
    }
}
