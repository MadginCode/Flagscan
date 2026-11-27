//! Archives and compression: zip (with password guessing), tar, 7z, gzip, zlib, raw deflate,
//! bzip2, xz, lzma, zstd.

use super::{Child, Scanner, util::read_limited};
use std::io::{Cursor, Read};

pub fn expand(sc: &Scanner, data: &[u8], kind: Option<&str>, kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let limit = sc.cfg.max_node_size;
    let Some(kind) = kind else { return };
    match kind {
        "zip" => zip(sc, data, kids, notes),
        "tar" => tar(data, limit, kids),
        "7z" => sevenz(sc, data, kids, notes),
        "rar" => notes.push("RAR archive: not extracted (use unrar / 7z and rescan the output)".into()),
        _ => {
            if let Some((label, out)) = decompress(kind, data, limit) {
                kids.push(Child::new(label, out).artifact());
            }
        }
    }
}

/// Single-stream decompression by kind. Also used by the carver to validate candidates.
pub fn decompress(kind: &str, data: &[u8], limit: usize) -> Option<(String, Vec<u8>)> {
    let out = match kind {
        "gzip" => read_limited(flate2::read::MultiGzDecoder::new(data), limit),
        "zlib" => read_limited(flate2::read::ZlibDecoder::new(data), limit),
        "bzip2" => read_limited(bzip2::read::MultiBzDecoder::new(data), limit),
        "zstd" => ruzstd::decoding::StreamingDecoder::new(data).ok().and_then(|d| read_limited(d, limit)),
        "xz" => {
            let mut out = Vec::new();
            let _ = lzma_rs::xz_decompress(&mut std::io::BufReader::new(data), &mut out);
            (!out.is_empty()).then(|| {
                out.truncate(limit);
                out
            })
        }
        "lzma" => {
            let mut out = Vec::new();
            let _ = lzma_rs::lzma_decompress(&mut std::io::BufReader::new(data), &mut out);
            (!out.is_empty()).then(|| {
                out.truncate(limit);
                out
            })
        }
        _ => None,
    }?;
    let label = match kind {
        "gzip" => {
            // Include the original file name stored in the gzip header when present.
            let name = flate2::read::GzDecoder::new(data).header().and_then(|h| h.filename().map(|f| String::from_utf8_lossy(f).into_owned()));
            match name {
                Some(n) => format!("gunzip:{n}"),
                None => "gunzip".into(),
            }
        }
        k => format!("{k} decompress"),
    };
    Some((label, out))
}

fn zip(sc: &Scanner, data: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let limit = sc.cfg.max_node_size;
    let Ok(mut ar) = zip::ZipArchive::new(Cursor::new(data)) else {
        notes.push("zip header found but archive could not be opened (damaged central directory?)".into());
        return;
    };
    let comment = ar.comment().to_vec();
    if !comment.is_empty() {
        kids.push(Child::new("zip comment", comment));
    }
    for i in 0..ar.len().min(5000) {
        let (name, encrypted, is_dir) = match ar.by_index_data(i) {
            Ok(e) => (e.name().map(|n| n.into_owned()).unwrap_or_else(|_| format!("entry{i}")), e.encrypted(), e.is_dir()),
            Err(_) => continue,
        };
        if is_dir {
            continue;
        }
        if !encrypted {
            if let Ok(f) = ar.by_index(i)
                && let Some(d) = read_limited(f, limit) {
                    kids.push(Child::new(format!("zip:{name}"), d).artifact());
                }
            continue;
        }
        let mut cracked = false;
        for pw in sc.passwords {
            let Ok(mut f) = ar.by_index_decrypt(i, pw) else { continue };
            let mut out = Vec::new();
            // A wrong ZipCrypto password usually fails the CRC check while reading.
            if f.by_ref().take(limit as u64).read_to_end(&mut out).is_ok() && !out.is_empty() {
                let shown = String::from_utf8_lossy(pw);
                kids.push(Child::new(format!("zip:{name} (password '{shown}')"), out).artifact());
                notes.push(format!("encrypted entry '{name}' opened with password '{shown}'"));
                cracked = true;
                break;
            }
        }
        if !cracked {
            notes.push(format!(
                "encrypted zip entry '{name}': password not in list. Add guesses in settings, or crack with zip2john + john / bkcrack (known plaintext)"
            ));
        }
    }
}

fn tar(data: &[u8], limit: usize, kids: &mut Vec<Child>) {
    let mut ar = tar::Archive::new(data);
    let Ok(entries) = ar.entries() else { return };
    for e in entries.flatten().take(5000) {
        if !e.header().entry_type().is_file() {
            continue;
        }
        let name = e.path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        if let Some(d) = read_limited(e, limit) {
            kids.push(Child::new(format!("tar:{name}"), d).artifact());
        }
    }
}

fn sevenz(sc: &Scanner, data: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let limit = sc.cfg.max_node_size;
    let Ok(tmp) = tempfile::tempdir() else { return };
    for pw in sc.passwords {
        let mut got = Vec::new();
        let pass = sevenz_rust::Password::from(String::from_utf8_lossy(pw).as_ref());
        let r = sevenz_rust::decompress_with_extract_fn_and_password(Cursor::new(data), tmp.path(), pass, |entry, reader, _| {
            if !entry.is_directory() {
                // Read strictly: with a wrong password the stream fails (LZMA or CRC error),
                // and that error must abort this attempt.
                let mut d = Vec::new();
                reader.take(limit as u64).read_to_end(&mut d).map_err(sevenz_rust::Error::io)?;
                got.push((entry.name().to_string(), d));
            }
            Ok(true)
        });
        if r.is_ok() || (pw.is_empty() && !got.is_empty()) {
            if !pw.is_empty() {
                notes.push(format!("7z opened with password '{}'", String::from_utf8_lossy(pw)));
            }
            for (n, d) in got {
                kids.push(Child::new(format!("7z:{n}"), d).artifact());
            }
            return;
        }
    }
    notes.push("7z archive could not be opened (password not in list?)".into());
}
