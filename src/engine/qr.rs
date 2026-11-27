//! QR code and barcode decoding (rxing / ZXing port). Runs on any decodable image, including
//! images that earlier steps produced: carved-out images, repaired PNGs, LSB-extracted files.

use super::Child;

const MAX_PIXELS: u64 = 8_000_000;

pub fn expand(data: &[u8], kind: Option<&str>, kids: &mut Vec<Child>, notes: &mut Vec<String>) {
    if !matches!(kind, Some("png" | "jpeg" | "gif" | "bmp" | "tiff" | "webp")) {
        return;
    }
    let Ok(img) = image::load_from_memory(data) else { return };
    let (w, h) = (img.width(), img.height());
    if (w as u64) * (h as u64) > MAX_PIXELS || w == 0 || h == 0 {
        return;
    }
    let luma = img.to_luma8().into_raw();
    let Ok(results) = rxing::helpers::detect_multiple_in_luma(luma, w, h) else { return };
    for r in results {
        let text = r.getText();
        if text.is_empty() {
            continue;
        }
        let fmt = format!("{:?}", r.getBarcodeFormat());
        notes.push(format!("{fmt} decoded: {}", preview(text)));
        kids.push(Child::new(format!("{fmt} payload"), text.as_bytes().to_vec()));
    }
}

fn preview(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        out.push('…');
    }
    out
}
