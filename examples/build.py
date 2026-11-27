"""Build the example challenges that ship inside the flagscan binary.

Usage: python3 examples/build.py path/to/flagscan

Generates the test challenges (tests/make_fixtures.py), adds two visual-only examples for the
Stego tools, writes examples/manifest.json (what each example teaches and its flag) and packs
everything into examples/examples.tar.gz, which src/engine/examples.rs embeds with include_bytes!.
The flagscan binary is used to check that every listed flag is really found.
"""
import io, json, os, random, shutil, subprocess, sys, tarfile, tempfile, wave, struct, math

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target", "release", "flagscan")

# Short description of the technique each example demonstrates, keyed by file name.
TECHNIQUES = {
    "01_plain.txt": "Flag in plain text",
    "02_b64.txt": "Base64",
    "03_triple.txt": "Base64 applied three times",
    "04_rot13_hex.txt": "ROT13, then hex",
    "05_xor.bin": "Single-byte XOR inside binary noise",
    "06_repxor.bin": "Repeating-key XOR (2-byte key)",
    "07_caesar.txt": "Caesar shift 7",
    "08_trailer.png": "Zip appended after PNG end, containing gzip of base64",
    "09_lsb.png": "LSB steganography (RGB, bit 0)",
    "10_lsb_b64.png": "LSB steganography carrying base64",
    "11_short.png": "PNG with its height cut; flagscan restores the full image (see Extracted files)",
    "12_text.png": "Base32 in a PNG tEXt chunk",
    "13_exif.jpg": "Reversed text in EXIF ImageDescription",
    "14_locked.zip": "Password-protected zip (common password), base64 inside",
    "15_archive.tar.xz": "URL-encoded text inside tar.xz",
    "16_http.pcap": "HTTP response split across TCP packets",
    "17_dns.pcap": "Base64 exfiltrated in DNS query names",
    "18_usb.pcap": "USB keyboard keystrokes",
    "19_wide.bin": "UTF-16 string inside binary noise",
    "20_morse.txt": "Morse code",
    "21_audio.wav": "LSB steganography in WAV samples",
    "22_doc.pdf": "Compressed PDF stream",
    "23_bz2.b64": "Base64 of bzip2",
    "24_zstd.bin": "Zstandard-compressed",
    "25_xored.dat": "Whole PNG XORed with 0x42, flag in a text chunk",
    "26_a85.txt": "Ascii85",
    "27_b58.txt": "Base58",
    "28_bin.txt": "Binary (01100110 ...)",
    "29_lsb_zip.png": "Zip hidden in LSB, base64 inside",
    "30_locked.7z": "Password-protected 7z (common password)",
    "33_xorzip.bin": "Zip XORed with a 3-byte key",
    "34_b45.txt": "Base45",
    "35_b91.txt": "Base91",
    "36_uu.txt": "Uuencode",
    "38_brainfuck.txt": "Brainfuck program that prints the flag",
    "39_vigenere.txt": "Vigenere cipher, key recovered from the flag prefix",
    "40_wordlist.zip": "Zip whose password is only in wordlist.txt",
    "41_qr.png": "QR code",
    "42_qr_b64.png": "QR code carrying base64",
    "43_qr_lsb.png": "QR code image hidden in LSB",
    "44_http_gzip.pcap": "Gzip + chunked HTTP response in a pcap",
    "45_http_upload.pcap": "File uploaded via multipart HTTP POST in a pcap",
    "46_pdf_filters.pdf": "PDF streams with LZW and ASCIIHex filters",
    "47_macro.doc": "VBA macro in an Office (OLE) document",
    "deep/nested/dir/31_reverse_b64.txt": "Reversed base64, nested in subfolders",
    "visual/plane.png": "Flag drawn into blue bit 0: open it in Stego tools > bit planes",
    "visual/spectrogram.wav": "Flag drawn into the spectrogram: open it in Stego tools",
}
SKIP = {"deep/32_noise.bin"}


def visual_examples(out):
    from PIL import Image, ImageDraw
    os.makedirs(os.path.join(out, "visual"), exist_ok=True)
    random.seed(7)
    w, h = 320, 80
    img = Image.new("RGB", (w, h))
    img.putdata([(random.randrange(256), random.randrange(256), random.randrange(256)) for _ in range(w * h)])
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).text((10, 32), "flag{drawn_in_a_bit_plane}", fill=1)
    px = img.load(); m = mask.load()
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            px[x, y] = (r, g, (b & 0xFE) | m[x, y])
    img.save(os.path.join(out, "visual", "plane.png"))

    # Draw text into a time/frequency grid, upscale it, and synthesise each column as a short
    # Hann-windowed burst of sines; overlapping the bursts avoids clicks that would smear the image.
    txt = Image.new("L", (84, 11), 0)
    ImageDraw.Draw(txt).text((1, 0), "flag{spectro}", fill=255)
    grid = txt.resize((84 * 6, 11 * 4), Image.NEAREST)
    gw, gh = grid.size
    g = grid.load()
    sr, hop, win = 16000, 256, 1024
    n = gw * hop + win
    samples = [0.0] * n
    freqs = [2500 + (gh - 1 - y) * 28 for y in range(gh)]  # top rows -> high frequency
    hann = [0.5 - 0.5 * math.cos(2 * math.pi * i / win) for i in range(win)]
    for x in range(gw):
        active = [freqs[y] for y in range(gh) if g[x, y] > 128]
        if not active:
            continue
        base = x * hop
        for i in range(win):
            t = (base + i) / sr
            samples[base + i] += hann[i] * sum(math.sin(2 * math.pi * f * t) for f in active)
    peak = max(1e-9, max(abs(s) for s in samples))
    pcm = b"".join(struct.pack("<h", int(s / peak * 20000)) for s in samples)
    with wave.open(os.path.join(out, "visual", "spectrogram.wav"), "wb") as wf:
        wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr); wf.writeframes(pcm)


def main():
    tmp = tempfile.mkdtemp(prefix="flagscan-examples-")
    files = os.path.join(tmp, "files")
    subprocess.run([sys.executable, os.path.join(ROOT, "tests", "make_fixtures.py"), files], check=True, stdout=subprocess.DEVNULL)
    for s in SKIP:
        p = os.path.join(files, s)
        if os.path.exists(p):
            os.remove(p)
    visual_examples(files)
    shutil.copy(os.path.join(tmp, "wordlist.txt"), os.path.join(files, "wordlist.txt"))

    # Which flag does each file yield? Ask the scanner, then keep the first flag per file.
    res = json.loads(subprocess.run(
        [BIN, "scan", files, "-f", "flag{}", "--wordlist", os.path.join(files, "wordlist.txt"), "--json"],
        check=True, capture_output=True).stdout)
    by_file = {}
    for f in res["findings"]:
        for chain in f["chains"]:
            name = chain[0].split("/", 1)[1] if "/" in chain[0] else chain[0]
            by_file.setdefault(name, set()).add(f["flag"])

    expected = [l.strip() for l in open(os.path.join(tmp, "expected.txt")) if l.strip()]
    entries = []
    for root, _, names in os.walk(files):
        for n in sorted(names):
            rel = os.path.relpath(os.path.join(root, n), files).replace(os.sep, "/")
            if rel == "wordlist.txt":
                continue
            if rel not in TECHNIQUES:
                sys.exit(f"no description for {rel}; add it to TECHNIQUES")
            flags = sorted(f for f in by_file.get(rel, ()) if f in expected)
            visual = rel.startswith("visual/") or rel == "11_short.png"
            entries.append({"file": rel, "technique": TECHNIQUES[rel], "flag": flags[0] if flags else None, "visual": visual})
    entries.sort(key=lambda e: e["file"])

    missing = [e["file"] for e in entries if not e["visual"] and not e["flag"]]
    if missing:
        sys.exit(f"scanner found no expected flag in: {missing}")

    manifest = {"version": 1, "wordlist": "wordlist.txt", "examples": entries}
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    with tarfile.open(os.path.join(HERE, "examples.tar.gz"), "w:gz", compresslevel=9) as tf:
        for root, _, names in os.walk(files):
            for n in sorted(names):
                full = os.path.join(root, n)
                info = tf.gettarinfo(full, arcname=os.path.relpath(full, files).replace(os.sep, "/"))
                info.mtime = 0; info.uid = info.gid = 0; info.uname = info.gname = ""
                with open(full, "rb") as fh:
                    tf.addfile(info, fh)
    shutil.rmtree(tmp)
    size = os.path.getsize(os.path.join(HERE, "examples.tar.gz"))
    print(f"{len(entries)} examples, {sum(1 for e in entries if e['flag'])} with flags, bundle {size // 1024} KB")


if __name__ == "__main__":
    main()
