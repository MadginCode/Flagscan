//! Least-significant-bit extraction (zsteg-style) for lossless images and WAV audio.

use super::{Child, Origin, util};

const MAX_PIXELS: u64 = 40_000_000;

fn lsb_child(label: String, data: Vec<u8>) -> Child {
    Child::new(label, data).with_origin(Origin { lsb: true, ..Default::default() })
}

/// Pack a stream of bits into bytes.
fn pack(bits: impl Iterator<Item = u8>, msb_first: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cur = 0u8;
    let mut n = 0;
    for b in bits {
        if msb_first {
            cur = (cur << 1) | b;
        } else {
            cur |= b << n;
        }
        n += 1;
        if n == 8 {
            out.push(cur);
            cur = 0;
            n = 0;
        }
    }
    out
}

pub fn expand(data: &[u8], kind: Option<&str>, kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    match kind {
        Some("png" | "bmp" | "gif" | "tiff" | "webp") => image_lsb(data, kids, notes),
        Some("wav") => wav_lsb(data, kids, notes),
        _ => {}
    }
}

fn image_lsb(data: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let Ok(reader) = image::ImageReader::new(std::io::Cursor::new(data)).with_guessed_format() else { return };
    let Ok((w, h)) = reader.into_dimensions() else { return };
    if (w as u64) * (h as u64) > MAX_PIXELS {
        notes.push(format!("image {w}x{h} too large for LSB analysis"));
        return;
    }
    let Ok(img) = image::load_from_memory(data) else { return };
    let has_alpha = img.color().has_alpha();
    let rgba = img.to_rgba8();
    let px = rgba.as_raw();
    let (w, h) = (w as usize, h as usize);

    let mut sets: Vec<(&str, Vec<usize>)> = vec![
        ("RGB", vec![0, 1, 2]),
        ("BGR", vec![2, 1, 0]),
        ("R", vec![0]),
        ("G", vec![1]),
        ("B", vec![2]),
    ];
    if has_alpha {
        sets.push(("RGBA", vec![0, 1, 2, 3]));
        sets.push(("A", vec![3]));
    }
    for (name, chans) in &sets {
        for nbits in [1u8, 2] {
            for (order, msb) in [("msb", true), ("lsb", false)] {
                let bits = (0..w * h).flat_map(|p| {
                    chans.iter().flat_map(move |&c| {
                        let v = px[p * 4 + c];
                        (0..nbits).rev().map(move |b| (v >> b) & 1)
                    })
                });
                let out = pack(bits, msb);
                report_text(&out, &format!("{name} b{nbits} {order}"), notes);
                kids.push(lsb_child(format!("LSB {name} b{nbits} {order}-first"), out));
            }
        }
    }
    // Column-major traversal, the next most common layout.
    let bits = (0..w).flat_map(|x| (0..h).flat_map(move |y| (0..3).map(move |c| px[(y * w + x) * 4 + c] & 1)));
    let out = pack(bits, true);
    report_text(&out, "RGB b1 msb (columns)", notes);
    kids.push(lsb_child("LSB RGB b1 msb-first, column order".into(), out));
}

fn report_text(out: &[u8], what: &str, notes: &mut Vec<String>) {
    let head = &out[..out.len().min(64)];
    let run = head.iter().take_while(|&&b| (0x20..0x7f).contains(&b) || b == b'\n').count();
    let distinct = head[..run].iter().collect::<std::collections::HashSet<_>>().len();
    if run >= 12 && distinct >= 6 {
        notes.push(format!("LSB {what} starts with readable text: \"{}\"", util::preview(head, 64)));
    } else if let Some(k) = util::sniff(out) {
        notes.push(format!("LSB {what} starts with a {k} file header"));
    }
}

fn wav_lsb(d: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    // Walk RIFF chunks to find fmt and data.
    let mut pos = 12;
    let mut bits_per_sample = 16u16;
    while pos + 8 <= d.len() {
        let id = &d[pos..pos + 4];
        let len = u32::from_le_bytes(d[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let body = &d[pos + 8..(pos + 8 + len).min(d.len())];
        if id == b"fmt " && body.len() >= 16 {
            bits_per_sample = u16::from_le_bytes([body[14], body[15]]);
        } else if id == b"data" {
            let step = (bits_per_sample as usize / 8).max(1);
            for (order, msb) in [("msb", true), ("lsb", false)] {
                let out = pack(body.chunks_exact(step).map(|s| s[0] & 1), msb);
                report_text(&out, &format!("WAV samples {order}"), notes);
                kids.push(lsb_child(format!("WAV sample LSB {order}-first"), out));
            }
        } else if !matches!(id, b"LIST" | b"fact" | b"cue " | b"smpl" | b"bext" | b"id3 " | b"PEAK" | b"JUNK") {
            notes.push(format!("unusual WAV chunk '{}'", String::from_utf8_lossy(id)));
            kids.push(Child::new(format!("WAV chunk '{}'", String::from_utf8_lossy(id)), body.to_vec()).artifact());
        }
        pos += 8 + len + (len & 1);
    }
}
