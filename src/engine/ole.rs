//! OLE / Compound File Binary (CFB) extraction: the container behind legacy .doc/.xls/.ppt and
//! the vbaProject.bin inside macro-enabled Office files. Streams are emitted as children, and VBA
//! module source (MS-OVBA RLE-compressed) is decompressed so flags in macros become readable.

use super::Child;

const SIG: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

pub fn is_ole(d: &[u8]) -> bool {
    d.starts_with(SIG)
}

pub fn expand(d: &[u8], kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    let Some(streams) = parse(d) else {
        notes.push("OLE compound file found but its FAT could not be parsed".into());
        return;
    };
    let mut saw_vba = false;
    for (name, data) in streams {
        let lname = name.to_ascii_lowercase();
        // VBA module streams hold compressed source after a small header; dir stream lists them.
        if saw_module(&lname) {
            saw_vba = true;
            if let Some(src) = decompress_vba_module(&data) {
                kids.push(Child::new(format!("OLE VBA {name}"), src));
                continue;
            }
        }
        kids.push(Child::new(format!("OLE stream {name}"), data).artifact());
    }
    if saw_vba {
        notes.push("Office file contains VBA macros (decompressed source extracted)".into());
    }
}

fn saw_module(lname: &str) -> bool {
    // Module streams live under a VBA storage; heuristic by name.
    !lname.contains("dir") && !lname.contains("_vba_project") && !lname.contains("project")
        && (lname.ends_with("module1") || lname.contains("module") || lname.contains("thisdocument") || lname.contains("sheet") || lname.contains("thisworkbook"))
}

struct Cfb<'a> {
    d: &'a [u8],
    sector: usize,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    mini_start: u32,
    mini_cutoff: u32,
}

fn rd_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().unwrap_or([0; 4]))
}

/// Returns (name, bytes) for every real stream in the compound file.
fn parse(d: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    if d.len() < 512 || !is_ole(d) {
        return None;
    }
    let sector = 1usize << u16::from_le_bytes([d[30], d[31]]);
    if !(64..=4096).contains(&sector) {
        return None;
    }
    let num_fat = rd_u32(d, 44) as usize;
    let dir_start = rd_u32(d, 48);
    let mini_cutoff = rd_u32(d, 56);
    let mini_fat_start = rd_u32(d, 60);
    let num_mini_fat = rd_u32(d, 64) as usize;
    let difat_start = rd_u32(d, 68);
    let num_difat = rd_u32(d, 72) as usize;

    let sect = |n: u32| -> Option<&[u8]> {
        let off = 512 + n as usize * sector;
        d.get(off..off + sector)
    };

    // Build the DIFAT (list of FAT sector numbers): first 109 are in the header.
    let mut fat_sectors: Vec<u32> = (0..109).map(|i| rd_u32(d, 76 + i * 4)).filter(|&s| s != 0xffffffff).collect();
    let mut ds = difat_start;
    for _ in 0..num_difat.min(4096) {
        let s = sect(ds)?;
        let per = sector / 4 - 1;
        for i in 0..per {
            let v = rd_u32(s, i * 4);
            if v != 0xffffffff {
                fat_sectors.push(v);
            }
        }
        ds = rd_u32(s, sector - 4);
        if ds == 0xfffffffe || ds == 0xffffffff {
            break;
        }
    }
    fat_sectors.truncate(num_fat.max(1).min(fat_sectors.len()).max(fat_sectors.len()));

    // Read the FAT.
    let mut fat = Vec::new();
    for &fs in &fat_sectors {
        let s = sect(fs)?;
        for i in 0..sector / 4 {
            fat.push(rd_u32(s, i * 4));
        }
    }
    if fat.is_empty() {
        return None;
    }

    let mut cfb = Cfb { d, sector, fat, mini_fat: vec![], mini_start: 0, mini_cutoff };

    // Mini FAT.
    let mut mf = mini_fat_start;
    for _ in 0..num_mini_fat.min(65536) {
        if mf == 0xfffffffe || mf == 0xffffffff {
            break;
        }
        let off = 512 + mf as usize * sector;
        let Some(s) = d.get(off..off + sector) else { break };
        for i in 0..sector / 4 {
            cfb.mini_fat.push(rd_u32(s, i * 4));
        }
        mf = *cfb.fat.get(mf as usize)?;
    }

    // Directory entries.
    let dir = cfb.read_chain(dir_start, usize::MAX)?;
    let root_mini_start = rd_u32(&dir, 116); // root entry's starting sector = mini stream
    let root_size = rd_u32(dir.get(120..124)?, 0);
    cfb.mini_start = root_mini_start;
    let _ = root_size;
    let mini_stream = cfb.read_chain(cfb.mini_start, usize::MAX).unwrap_or_default();

    let mut out = Vec::new();
    let count = dir.len() / 128;
    for i in 0..count.min(5000) {
        let e = &dir[i * 128..i * 128 + 128];
        let nlen = u16::from_le_bytes([e[64], e[65]]) as usize;
        if nlen < 2 || e[66] != 2 {
            continue; // type 2 = stream
        }
        let name: String = e[..nlen.saturating_sub(2).min(62)]
            .chunks(2)
            .map(|c| char::from_u32(u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]) as u32).unwrap_or('?'))
            .collect();
        let start = rd_u32(e, 116);
        let size = rd_u32(e, 120) as usize;
        let data = if (size as u32) < cfb.mini_cutoff {
            read_mini(&mini_stream, &cfb.mini_fat, start, size)
        } else {
            cfb.read_chain(start, size)?
        };
        if !data.is_empty() {
            out.push((name, data));
        }
    }
    Some(out)
}

impl Cfb<'_> {
    fn read_chain(&self, start: u32, limit: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut cur = start;
        let mut guard = 0;
        while cur != 0xfffffffe && cur != 0xffffffff && (cur as usize) < self.fat.len() {
            let off = 512 + cur as usize * self.sector;
            out.extend_from_slice(self.d.get(off..off + self.sector)?);
            cur = self.fat[cur as usize];
            guard += 1;
            if out.len() >= limit || guard > 1_000_000 {
                break;
            }
        }
        if limit != usize::MAX {
            out.truncate(limit);
        }
        Some(out)
    }
}

fn read_mini(mini_stream: &[u8], mini_fat: &[u32], start: u32, size: usize) -> Vec<u8> {
    const MINI: usize = 64;
    let mut out = Vec::new();
    let mut cur = start;
    let mut guard = 0;
    while cur != 0xfffffffe && cur != 0xffffffff && (cur as usize) < mini_fat.len() {
        let off = cur as usize * MINI;
        if off + MINI <= mini_stream.len() {
            out.extend_from_slice(&mini_stream[off..off + MINI]);
        }
        cur = mini_fat[cur as usize];
        guard += 1;
        if out.len() >= size || guard > 1_000_000 {
            break;
        }
    }
    out.truncate(size);
    out
}

/// MS-OVBA CompressedContainer: find the 0x01 signature, then decode its chunks.
fn decompress_vba_module(stream: &[u8]) -> Option<Vec<u8>> {
    let start = stream.iter().position(|&b| b == 0x01)?;
    decompress_container(&stream[start..])
}

fn decompress_container(d: &[u8]) -> Option<Vec<u8>> {
    if d.first() != Some(&0x01) {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = 1;
    while pos + 2 <= d.len() {
        let header = u16::from_le_bytes([d[pos], d[pos + 1]]);
        let size = (header & 0x0fff) as usize + 3;
        let compressed = header & 0x8000 != 0;
        let chunk_start = pos + 2;
        let chunk_end = (chunk_start + size - 2).min(d.len());
        let chunk = &d[chunk_start..chunk_end];
        pos = chunk_end;
        if !compressed {
            out.extend_from_slice(&chunk[..chunk.len().min(4096)]);
            continue;
        }
        decode_chunk(chunk, &mut out);
        if out.len() > 64 << 20 {
            break;
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vba_copytoken() {
        // Container: 0x01, header 0xB003 (compressed, size 6), then one literal 'A' and a copy
        // token (offset 1, length 7) -> "AAAAAAAA".
        let c = [0x01u8, 0x03, 0xB0, 0x02, b'A', 0x04, 0x00];
        assert_eq!(decompress_container(&c).unwrap(), b"AAAAAAAA");
    }
}

fn decode_chunk(chunk: &[u8], out: &mut Vec<u8>) {
    let chunk_base = out.len();
    let mut i = 0;
    while i < chunk.len() {
        let flags = chunk[i];
        i += 1;
        for bit in 0..8 {
            if i >= chunk.len() {
                return;
            }
            if flags & (1 << bit) == 0 {
                out.push(chunk[i]);
                i += 1;
            } else {
                if i + 1 >= chunk.len() {
                    return;
                }
                let token = u16::from_le_bytes([chunk[i], chunk[i + 1]]);
                i += 2;
                let decomp = out.len() - chunk_base;
                let bitcount = (32 - ((decomp.max(1) - 1) as u32).leading_zeros()).max(4);
                let len_mask = (1u16 << (16 - bitcount)) - 1;
                let length = (token & len_mask) as usize + 3;
                let offset = (token >> (16 - bitcount)) as usize + 1;
                if offset > out.len() {
                    return;
                }
                for _ in 0..length {
                    out.push(out[out.len() - offset]);
                }
            }
        }
    }
}
