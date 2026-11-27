//! Interactive helpers for the "needs eyes" cases the scanner can't read on its own: rendering an
//! image's bit planes (a flag drawn into one plane) and an audio spectrogram (a flag drawn in the
//! frequency domain). Both return PNG bytes for the web UI.

use image::{GrayImage, ImageFormat, Luma, RgbImage};
use rustfft::{FftPlanner, num_complex::Complex};
use std::io::Cursor;

const MAX_PIXELS: u64 = 16_000_000;

fn to_png(img: image::DynamicImage) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png).ok()?;
    Some(buf)
}

pub struct Plane {
    pub label: String,
    pub png: Vec<u8>,
}

/// One image per channel per bit. The bit-0 planes are the usual LSB hiding spot.
pub fn bit_planes(data: &[u8]) -> Result<Vec<Plane>, String> {
    let img = image::load_from_memory(data).map_err(|e| e.to_string())?;
    if (img.width() as u64) * (img.height() as u64) > MAX_PIXELS {
        return Err("image too large for plane rendering".into());
    }
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let has_alpha = img.color().has_alpha();
    let channels: &[(usize, &str)] = if has_alpha { &[(0, "R"), (1, "G"), (2, "B"), (3, "A")] } else { &[(0, "R"), (1, "G"), (2, "B")] };
    let mut out = Vec::new();
    for &(c, cname) in channels {
        for bit in 0..8u8 {
            let mut plane = GrayImage::new(w, h);
            for (x, y, px) in rgba.enumerate_pixels() {
                let v = ((px.0[c] >> bit) & 1) * 255;
                plane.put_pixel(x, y, Luma([v]));
            }
            if let Some(png) = to_png(plane.into()) {
                out.push(Plane { label: format!("{cname} bit {bit}"), png });
            }
        }
    }
    Ok(out)
}

/// Shannon-magnitude spectrogram of mono audio from a WAV file.
pub fn spectrogram(data: &[u8]) -> Result<Vec<u8>, String> {
    let samples = wav_mono(data).ok_or("not a readable PCM WAV file")?;
    if samples.len() < 2048 {
        return Err("audio too short for a spectrogram".into());
    }
    let win = 1024usize;
    let hop = 256usize;
    let frames = (samples.len() - win) / hop;
    if frames == 0 {
        return Err("audio too short".into());
    }
    let width = frames.min(4000) as u32;
    let height = (win / 2) as u32;

    // Hann window and a reusable forward FFT.
    let hann: Vec<f32> = (0..win).map(|i| 0.5 - 0.5 * (std::f32::consts::TAU * i as f32 / win as f32).cos()).collect();
    let fft = FftPlanner::<f32>::new().plan_fft_forward(win);

    let mut mags = vec![0f32; width as usize * height as usize];
    let mut peak = 1e-9f32;
    for f in 0..width as usize {
        let start = f * hop;
        let mut buf: Vec<Complex<f32>> = (0..win).map(|i| Complex::new(samples[start + i] * hann[i], 0.0)).collect();
        fft.process(&mut buf);
        for y in 0..height as usize {
            let m = buf[y].norm();
            let db = 20.0 * (m + 1e-9).log10();
            mags[y * width as usize + f] = db;
            if db > peak {
                peak = db;
            }
        }
    }
    let floor = peak - 80.0; // 80 dB dynamic range

    let mut img = RgbImage::new(width, height);
    for y in 0..height as usize {
        for x in 0..width as usize {
            let norm = ((mags[y * width as usize + x] - floor) / (peak - floor)).clamp(0.0, 1.0);
            // Low frequencies at the bottom.
            img.put_pixel(x as u32, height - 1 - y as u32, Luma8Magma(norm).into());
        }
    }
    to_png(img.into()).ok_or_else(|| "png encode failed".into())
}

/// A compact magma-like colormap: dark purple -> orange -> white.
struct Luma8Magma(f32);
impl From<Luma8Magma> for image::Rgb<u8> {
    fn from(m: Luma8Magma) -> Self {
        let t = m.0.clamp(0.0, 1.0);
        let r = (255.0 * (t * 1.6).min(1.0)).round() as u8;
        let g = (255.0 * ((t - 0.3) * 1.7).clamp(0.0, 1.0)).round() as u8;
        let b = (255.0 * ((t - 0.1).clamp(0.0, 1.0).powf(1.5) * 0.9 + 0.15 * (1.0 - t)).clamp(0.0, 1.0)).round() as u8;
        image::Rgb([r, g, b])
    }
}

/// Mono f32 samples in [-1, 1] from a PCM WAV (8/16/24/32-bit, averaging channels).
fn wav_mono(d: &[u8]) -> Option<Vec<f32>> {
    if d.len() < 12 || &d[0..4] != b"RIFF" || &d[8..12] != b"WAVE" {
        return None;
    }
    let mut pos = 12;
    let (mut channels, mut bits) = (1u16, 16u16);
    let mut samples = Vec::new();
    while pos + 8 <= d.len() {
        let id = &d[pos..pos + 4];
        let len = u32::from_le_bytes(d[pos + 4..pos + 8].try_into().ok()?) as usize;
        let body = &d[pos + 8..(pos + 8 + len).min(d.len())];
        if id == b"fmt " && body.len() >= 16 {
            channels = u16::from_le_bytes([body[2], body[3]]).max(1);
            bits = u16::from_le_bytes([body[14], body[15]]);
        } else if id == b"data" {
            let bytes = (bits / 8) as usize;
            if bytes == 0 {
                return None;
            }
            for frame in body.chunks_exact(bytes * channels as usize) {
                let mut acc = 0f32;
                for ch in 0..channels as usize {
                    let s = &frame[ch * bytes..ch * bytes + bytes];
                    acc += match bits {
                        8 => (s[0] as f32 - 128.0) / 128.0,
                        16 => i16::from_le_bytes([s[0], s[1]]) as f32 / 32768.0,
                        24 => (((i32::from_le_bytes([s[0], s[1], s[2], 0]) << 8) >> 8) as f32) / 8_388_608.0,
                        32 => i32::from_le_bytes([s[0], s[1], s[2], s[3]]) as f32 / 2_147_483_648.0,
                        _ => 0.0,
                    };
                }
                samples.push(acc / channels as f32);
            }
        }
        pos += 8 + len + (len & 1);
    }
    (!samples.is_empty()).then_some(samples)
}
