//! Format-aware metadata extraction: PNG chunks + IHDR/size repair, JPEG comments + trailer,
//! EXIF, PDF streams, pcap/pcapng flows (TCP/UDP/ICMP, DNS names, USB keyboard).

use super::{Child, Origin, util};
use flate2::Crc;
use std::collections::{BTreeMap, HashSet};
use std::io::Cursor;

fn be32(d: &[u8]) -> u32 {
    u32::from_be_bytes(d[..4].try_into().unwrap())
}

fn text_child(label: impl Into<String>, d: Vec<u8>) -> Child {
    Child::new(label, d).with_origin(Origin { text_only: true, ..Default::default() })
}

pub fn expand(data: &[u8], kind: Option<&str>, kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    match kind {
        Some("png") => png(data, kids, notes),
        Some("jpeg") => jpeg(data, kids, notes),
        Some("pdf") => pdf(data, kids, notes),
        Some("pcap") | Some("pcapng") => pcap(data, kind == Some("pcapng"), kids, notes),
        None => repair_magic(data, kids, notes),
        _ => {}
    }
    if matches!(kind, Some("png" | "jpeg" | "tiff" | "webp")) {
        exif(data, kids);
    }
}

/// Files whose magic bytes were tampered with but whose structure is intact.
fn repair_magic(d: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    if d.len() > 33 && &d[12..16] == b"IHDR" && !d.starts_with(b"\x89PNG\r\n\x1a\n") {
        let mut f = d.to_vec();
        f[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        notes.push("PNG with a corrupted signature: repaired copy extracted".into());
        kids.push(Child::new("PNG signature repaired", f).artifact());
    }
    if d.len() > 12 && &d[6..10] == b"JFIF" && !d.starts_with(b"\xff\xd8") {
        let mut f = d.to_vec();
        f[..4].copy_from_slice(b"\xff\xd8\xff\xe0");
        notes.push("JPEG with a corrupted signature: repaired copy extracted".into());
        kids.push(Child::new("JPEG signature repaired", f).artifact());
    }
}

const PNG_STD: &[&[u8; 4]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP", b"mDCv",
    b"cLLi", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"eXIf", b"tIME", b"acTL", b"fcTL", b"fdAT", b"oFFs", b"pCAL",
    b"sCAL", b"sTER", b"vpAg", b"iDOT", b"CgBI", b"tEXt", b"zTXt", b"iTXt",
];

fn crc(parts: &[&[u8]]) -> u32 {
    let mut c = Crc::new();
    for p in parts {
        c.update(p);
    }
    c.sum()
}

fn png(d: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let mut pos = 8;
    let mut idat = Vec::new();
    let mut ihdr: Option<(usize, [u8; 13])> = None;
    let mut ihdr_crc_ok = true;
    while pos + 12 <= d.len() {
        let len = be32(&d[pos..]) as usize;
        let ty: [u8; 4] = d[pos + 4..pos + 8].try_into().unwrap();
        if pos + 12 + len > d.len() {
            notes.push(format!("PNG chunk '{}' at 0x{pos:x} is truncated", String::from_utf8_lossy(&ty)));
            break;
        }
        let body = &d[pos + 8..pos + 8 + len];
        let stored = be32(&d[pos + 8 + len..]);
        let ok = crc(&[&ty, body]) == stored;
        let tname = String::from_utf8_lossy(&ty).into_owned();
        match &ty {
            b"IHDR" if len == 13 => {
                ihdr = Some((pos, body.try_into().unwrap()));
                ihdr_crc_ok = ok;
            }
            b"IDAT" => idat.extend_from_slice(body),
            b"tEXt" => {
                let (k, v) = split_nul(body);
                kids.push(text_child(format!("PNG tEXt '{}'", String::from_utf8_lossy(k)), v.to_vec()));
            }
            b"zTXt" => {
                let (k, v) = split_nul(body);
                if v.len() > 1
                    && let Some(t) = util::read_limited(flate2::read::ZlibDecoder::new(&v[1..]), 1 << 24) {
                        kids.push(text_child(format!("PNG zTXt '{}'", String::from_utf8_lossy(k)), t));
                    }
            }
            b"iTXt" => {
                let (k, rest) = split_nul(body);
                if rest.len() > 2 {
                    let compressed = rest[0] == 1;
                    let (_, rest2) = split_nul(&rest[2..]);
                    let (_, text) = split_nul(rest2);
                    let t = if compressed { util::read_limited(flate2::read::ZlibDecoder::new(text), 1 << 24) } else { Some(text.to_vec()) };
                    if let Some(t) = t {
                        kids.push(text_child(format!("PNG iTXt '{}'", String::from_utf8_lossy(k)), t));
                    }
                }
            }
            b"IEND" => {
                let after = pos + 12 + len;
                if after < d.len() {
                    notes.push(format!("{} bytes of data after PNG IEND", d.len() - after));
                    kids.push(Child::new("after PNG IEND", d[after..].to_vec()).artifact());
                }
                break;
            }
            t if !PNG_STD.contains(&t) => {
                notes.push(format!("non-standard PNG chunk '{tname}' ({len} bytes)"));
                kids.push(Child::new(format!("PNG chunk '{tname}'"), body.to_vec()).artifact());
            }
            _ => {}
        }
        if !ok && &ty != b"IHDR" {
            notes.push(format!("PNG chunk '{tname}' at 0x{pos:x} has a bad CRC (modified?)"));
        }
        pos += 12 + len;
    }

    let Some((ipos, h)) = ihdr else { return };
    let w = be32(&h[0..]);
    let hgt = be32(&h[4..]);
    let rebuild = |nw: u32, nh: u32| {
        let mut f = d.to_vec();
        f[ipos + 8..ipos + 12].copy_from_slice(&nw.to_be_bytes());
        f[ipos + 12..ipos + 16].copy_from_slice(&nh.to_be_bytes());
        let c = crc(&[b"IHDR", &f[ipos + 8..ipos + 21]]);
        f[ipos + 21..ipos + 25].copy_from_slice(&c.to_be_bytes());
        f
    };

    if !ihdr_crc_ok {
        let stored = be32(&d[ipos + 21..]);
        let tail = &h[8..];
        let check = |nw: u32, nh: u32| crc(&[b"IHDR", &nw.to_be_bytes(), &nh.to_be_bytes(), tail]) == stored;
        let found = (1..=16384).find(|&nh| check(w, nh)).map(|nh| (w, nh))
            .or_else(|| (1..=16384).find(|&nw| check(nw, hgt)).map(|nw| (nw, hgt)))
            .or_else(|| (1..=2500u32).flat_map(|a| (1..=2500u32).map(move |b| (a, b))).find(|&(a, b)| check(a, b)));
        match found {
            Some((nw, nh)) => {
                notes.push(format!("PNG IHDR CRC mismatch: header says {w}x{hgt}, CRC matches {nw}x{nh}. Repaired image extracted: open it to see the hidden part"));
                kids.push(Child::new(format!("PNG resized to {nw}x{nh}"), rebuild(nw, nh)).artifact());
            }
            None => notes.push("PNG IHDR CRC mismatch, no width/height combination matches".into()),
        }
        return;
    }

    // CRC is valid, but the compressed pixel data may hold more rows than the header admits.
    let (depth, ctype, interlace) = (h[8] as u64, h[9], h[12]);
    let ch = match ctype { 0 => 1, 2 => 3, 3 => 1, 4 => 2, 6 => 4, _ => return };
    if interlace != 0 || w == 0 {
        return;
    }
    let row = (w as u64 * ch * depth).div_ceil(8) + 1;
    if let Some(raw) = util::read_limited(flate2::read::ZlibDecoder::new(&idat[..]), 512 << 20) {
        let rows = raw.len() as u64 / row;
        if rows > hgt as u64 {
            notes.push(format!("PNG pixel data holds {rows} rows but the header says {hgt}: taller image extracted"));
            kids.push(Child::new(format!("PNG resized to {w}x{rows}"), rebuild(w, rows as u32)).artifact());
        }
    }
}

fn split_nul(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&x| x == 0) {
        Some(i) => (&b[..i], &b[i + 1..]),
        None => (b, &[]),
    }
}

fn jpeg(d: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let mut pos = 2;
    let mut ncom = 0;
    while pos + 4 <= d.len() {
        if d[pos] != 0xff {
            return;
        }
        let m = d[pos + 1];
        if m == 0xff {
            pos += 1;
            continue;
        }
        if m == 0xd9 {
            let after = pos + 2;
            if after < d.len() {
                notes.push(format!("{} bytes of data after JPEG end marker", d.len() - after));
                kids.push(Child::new("after JPEG EOI", d[after..].to_vec()).artifact());
            }
            return;
        }
        if m == 0x01 || (0xd0..=0xd8).contains(&m) {
            pos += 2;
            continue;
        }
        let len = u16::from_be_bytes([d[pos + 2], d[pos + 3]]) as usize;
        let seg_end = (pos + 2 + len).min(d.len());
        let body = &d[(pos + 4).min(seg_end)..seg_end];
        if m == 0xfe {
            ncom += 1;
            kids.push(text_child(format!("JPEG comment #{ncom}"), body.to_vec()));
        }
        pos = seg_end;
        if m == 0xda {
            // Skip entropy-coded data up to the next real marker.
            while pos + 1 < d.len() {
                if d[pos] == 0xff && d[pos + 1] != 0 && !(0xd0..=0xd7).contains(&d[pos + 1]) {
                    break;
                }
                pos += 1;
            }
        }
    }
}

fn exif(d: &[u8], kids: &mut Vec<Child>) {
    let Ok(ex) = exif::Reader::new().read_from_container(&mut Cursor::new(d)) else { return };
    let mut out = String::new();
    for f in ex.fields() {
        out.push_str(&format!("{}: {}\n", f.tag, f.display_value().with_unit(&ex)));
        // Raw bytes too: display_value escapes undefined/UTF-16 fields (XPComment...).
        if let exif::Value::Undefined(b, _) | exif::Value::Byte(b) = &f.value {
            out.push_str(&String::from_utf8_lossy(b).replace('\0', ""));
            out.push('\n');
        }
    }
    if !out.is_empty() {
        kids.push(Child::new("EXIF", out.into_bytes()));
    }
}

fn pdf(d: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let finder = memchr::memmem::Finder::new(b"stream");
    let endf = memchr::memmem::Finder::new(b"endstream");
    let mut pos = 0;
    let mut n = 0;
    while let Some(i) = finder.find(&d[pos..]) {
        let s = pos + i;
        pos = s + 6;
        if s >= 3 && &d[s - 3..s] == b"end" {
            continue;
        }
        let mut start = s + 6;
        if d.get(start) == Some(&b'\r') {
            start += 1;
        }
        if d.get(start) == Some(&b'\n') {
            start += 1;
        }
        let Some(e) = endf.find(&d[start..]) else { break };
        let body = &d[start..start + e];
        n += 1;
        if let Some(out) = util::read_limited(flate2::read::ZlibDecoder::new(body), 256 << 20) {
            let c = Child::new(format!("PDF stream #{n} inflated"), out);
            kids.push(if util::sniff(&c.data).is_some() { c.artifact() } else { c });
        }
        pos = start + e + 9;
        if n > 5000 {
            break;
        }
    }
    for (needle, msg) in [(&b"/EmbeddedFile"[..], "PDF has embedded files"), (b"/JavaScript", "PDF contains JavaScript"), (b"/JS", "PDF contains JS actions")] {
        if memchr::memmem::find(d, needle).is_some() {
            notes.push(msg.into());
        }
    }
}

// ---------------------------------------------------------------- pcap

struct Flows {
    data: BTreeMap<String, Vec<u8>>,
    seen_seq: HashSet<(String, u32, usize)>,
    dns: Vec<String>,
    usb_kbd: Vec<[u8; 8]>,
    linktypes: HashSet<u32>,
}

fn pcap(d: &[u8], ng: bool, kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let mut fl = Flows { data: BTreeMap::new(), seen_seq: HashSet::new(), dns: vec![], usb_kbd: vec![], linktypes: HashSet::new() };
    if ng { pcapng_packets(d, &mut fl) } else { pcap_packets(d, &mut fl) };
    let total = fl.data.len();
    for (k, v) in fl.data.into_iter().take(1000) {
        if !v.is_empty() {
            kids.push(Child::new(k, v).artifact());
        }
    }
    if total > 1000 {
        notes.push(format!("{total} flows; only the first 1000 were extracted"));
    }
    if !fl.dns.is_empty() {
        let mut uniq: Vec<String> = Vec::new();
        for q in &fl.dns {
            if uniq.last() != Some(q) {
                uniq.push(q.clone());
            }
        }
        kids.push(Child::new("DNS query names", uniq.join("\n").into_bytes()));
        // Exfiltration via the first label of each query.
        let labels: String = uniq.iter().filter_map(|q| q.split('.').next()).collect();
        kids.push(Child::new("DNS first labels joined", labels.into_bytes()));
    }
    if !fl.usb_kbd.is_empty() {
        let text = hid_keys(&fl.usb_kbd);
        if !text.is_empty() {
            notes.push(format!("USB keyboard capture decoded ({} chars)", text.len()));
            kids.push(Child::new("USB keyboard keystrokes", text.into_bytes()).artifact());
        }
    }
    for lt in fl.linktypes {
        if !matches!(lt, 0 | 1 | 12 | 14 | 101 | 108 | 113 | 220 | 228 | 229 | 249 | 276) {
            notes.push(format!("pcap link type {lt} not decoded; only raw scanning applies"));
        }
    }
}

fn pcap_packets(d: &[u8], fl: &mut Flows) {
    if d.len() < 24 {
        return;
    }
    let le = matches!(&d[..4], b"\xd4\xc3\xb2\xa1" | b"\x4d\x3c\xb2\xa1");
    let u32at = |p: usize| {
        let b: [u8; 4] = d[p..p + 4].try_into().unwrap();
        if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let lt = u32at(20) & 0xffff;
    let mut pos = 24;
    while pos + 16 <= d.len() {
        let incl = u32at(pos + 8) as usize;
        let s = pos + 16;
        if s + incl > d.len() {
            break;
        }
        packet(lt, &d[s..s + incl], fl);
        pos = s + incl;
    }
}

fn pcapng_packets(d: &[u8], fl: &mut Flows) {
    let mut le = true;
    let mut ifaces: Vec<u32> = vec![];
    let mut pos = 0;
    while pos + 12 <= d.len() {
        let rd = |p: usize, le: bool| {
            let b: [u8; 4] = d[p..p + 4].try_into().unwrap();
            if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
        };
        let ty = u32::from_le_bytes(d[pos..pos + 4].try_into().unwrap());
        if ty == 0x0a0d0d0a {
            le = &d[pos + 8..pos + 12] == b"\x4d\x3c\x2b\x1a";
            ifaces.clear();
        }
        let blen = rd(pos + 4, le) as usize;
        if blen < 12 || pos + blen > d.len() {
            break;
        }
        let b = &d[pos..pos + blen];
        match rd(pos, le) {
            1 if blen >= 16 => {
                let lt = if le { u16::from_le_bytes([b[8], b[9]]) } else { u16::from_be_bytes([b[8], b[9]]) };
                ifaces.push(lt as u32);
            }
            6 if blen >= 32 => {
                let iface = rd(pos + 8, le) as usize;
                let cap = rd(pos + 20, le) as usize;
                if 28 + cap <= blen {
                    packet(*ifaces.get(iface).unwrap_or(&1), &b[28..28 + cap], fl);
                }
            }
            3 if blen >= 16 => {
                let len = (rd(pos + 8, le) as usize).min(blen - 16);
                packet(*ifaces.first().unwrap_or(&1), &b[12..12 + len], fl);
            }
            _ => {}
        }
        pos += blen;
    }
}

fn packet(lt: u32, p: &[u8], fl: &mut Flows) {
    fl.linktypes.insert(lt);
    let ip = match lt {
        1 => {
            if p.len() < 14 {
                return;
            }
            let mut et = u16::from_be_bytes([p[12], p[13]]);
            let mut off = 14;
            while (et == 0x8100 || et == 0x88a8) && p.len() >= off + 4 {
                et = u16::from_be_bytes([p[off + 2], p[off + 3]]);
                off += 4;
            }
            if et != 0x0800 && et != 0x86dd {
                return;
            }
            &p[off..]
        }
        0 | 108 => p.get(4..).unwrap_or(&[]),
        12 | 14 | 101 | 228 | 229 => p,
        113 => p.get(16..).unwrap_or(&[]),
        276 => p.get(20..).unwrap_or(&[]),
        249 => {
            // USBPcap: little-endian header length, then the transfer data.
            if p.len() > 2 {
                let hl = u16::from_le_bytes([p[0], p[1]]) as usize;
                usb_data(p.get(hl..).unwrap_or(&[]), fl);
            }
            return;
        }
        220 => {
            usb_data(p.get(64..).unwrap_or(&[]), fl);
            return;
        }
        _ => return,
    };
    ip_packet(ip, fl);
}

fn usb_data(d: &[u8], fl: &mut Flows) {
    if d.len() == 8 && d[1] == 0 && d[2..].iter().all(|&k| k <= 0x65) {
        fl.usb_kbd.push(d.try_into().unwrap());
    }
}

fn ip_packet(ip: &[u8], fl: &mut Flows) {
    if ip.is_empty() {
        return;
    }
    let (proto, src, dst, l4) = match ip[0] >> 4 {
        4 if ip.len() >= 20 => {
            let ihl = (ip[0] & 0xf) as usize * 4;
            let tot = (u16::from_be_bytes([ip[2], ip[3]]) as usize).clamp(ihl, ip.len());
            if ihl < 20 || ip.len() < ihl {
                return;
            }
            let a = |o: usize| format!("{}.{}.{}.{}", ip[o], ip[o + 1], ip[o + 2], ip[o + 3]);
            (ip[9], a(12), a(16), &ip[ihl..tot])
        }
        6 if ip.len() >= 40 => {
            let a = |o: usize| std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[o..o + 16]).unwrap()).to_string();
            let plen = (u16::from_be_bytes([ip[4], ip[5]]) as usize + 40).min(ip.len());
            (ip[6], a(8), a(24), &ip[40..plen])
        }
        _ => return,
    };
    match proto {
        6 if l4.len() >= 20 => {
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            let seq = be32(&l4[4..]);
            let off = ((l4[12] >> 4) as usize * 4).min(l4.len());
            let payload = &l4[off..];
            if payload.is_empty() {
                return;
            }
            let key = format!("tcp {src}:{sp} > {dst}:{dp}");
            if fl.seen_seq.insert((key.clone(), seq, payload.len())) {
                fl.data.entry(key).or_default().extend_from_slice(payload);
            }
        }
        17 if l4.len() >= 8 => {
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            let payload = &l4[8..];
            if (dp == 53 || sp == 53 || dp == 5353) && payload.len() > 12
                && let Some(q) = dns_qname(payload)
                    && (dp == 53 || dp == 5353) {
                        fl.dns.push(q);
                    }
            fl.data.entry(format!("udp {src}:{sp} > {dst}:{dp}")).or_default().extend_from_slice(payload);
        }
        1 | 58 if l4.len() > 8 => {
            fl.data.entry(format!("icmp {src} > {dst}")).or_default().extend_from_slice(&l4[8..]);
        }
        _ => {}
    }
}

fn dns_qname(p: &[u8]) -> Option<String> {
    let mut pos = 12;
    let mut labels = vec![];
    while pos < p.len() {
        let l = p[pos] as usize;
        if l == 0 || l >= 64 {
            break;
        }
        labels.push(String::from_utf8_lossy(p.get(pos + 1..pos + 1 + l)?).into_owned());
        pos += 1 + l;
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

fn hid_keys(reports: &[[u8; 8]]) -> String {
    const N: &str = "abcdefghijklmnopqrstuvwxyz1234567890\n\x1b\x08\t -=[]\\#;'`,./";
    const S: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()\n\x1b\x08\t _+{}|~:\"~<>?";
    let mut out = String::new();
    let mut prev = [0u8; 6];
    let mut caps = false;
    for r in reports {
        let shift = r[0] & 0x22 != 0;
        for &k in &r[2..8] {
            if k == 0 || prev.contains(&k) {
                continue;
            }
            if k == 0x39 {
                caps = !caps;
                continue;
            }
            if (4..=0x38).contains(&k) {
                let i = (k - 4) as usize;
                let upper = if (4..=0x1d).contains(&k) { shift ^ caps } else { shift };
                let c = if upper { S.as_bytes()[i] } else { N.as_bytes()[i] } as char;
                match c {
                    '\x08' => {
                        out.pop();
                    }
                    '\x1b' => {}
                    c => out.push(c),
                }
            }
        }
        prev.copy_from_slice(&r[2..8]);
    }
    out
}
