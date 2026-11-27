"""Generate layered CTF-style forensic challenges. Each one hides a unique flag.
Writes fixtures/ and expected.txt (one expected flag per line)."""
import base64, binascii, bz2, codecs, gzip, io, lzma, os, random, struct, subprocess, sys, tarfile, wave, zipfile, zlib
from PIL import Image, PngImagePlugin
import py7zr, zstandard

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
random.seed(1337)
expected = []

def w(name, data, flag):
    p = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    if flag:
        expected.append(flag)

def noise(n):
    return bytes(random.getrandbits(8) for _ in range(n))

def png_bytes(img, **kw):
    b = io.BytesIO(); img.save(b, "PNG", **kw); return b.getvalue()

def lsb_embed(payload, size=(120, 80), chans=3):
    img = Image.new("RGB", size)
    px = [tuple(random.randrange(256) for _ in range(3)) for _ in range(size[0] * size[1])]
    bits = [(byte >> (7 - i)) & 1 for byte in payload for i in range(8)]
    out, k = [], 0
    for p in px:
        p = list(p)
        for c in range(chans):
            if k < len(bits):
                p[c] = (p[c] & ~1) | bits[k]; k += 1
        out.append(tuple(p))
    img.putdata(out)
    return png_bytes(img)

F = lambda s: ("flag{%s}" % s)

w("01_plain.txt", b"nothing here\n" + F("plain_text").encode() + b"\n", F("plain_text"))
w("02_b64.txt", base64.b64encode(F("base64_one").encode()), F("base64_one"))
t = F("triple_b64").encode()
for _ in range(3): t = base64.b64encode(t)
w("03_triple.txt", t, F("triple_b64"))
w("04_rot13_hex.txt", binascii.hexlify(codecs.encode(F("rot13_then_hex"), "rot13").encode()), F("rot13_then_hex"))
w("05_xor.bin", bytes(b ^ 0x37 for b in noise(200) + F("single_xor").encode() + noise(100)), F("single_xor"))
key = b"k3"
w("06_repxor.bin", bytes(b ^ key[i % 2] for i, b in enumerate(b"header data " + F("repeat_xor").encode() + b" trailer")), F("repeat_xor"))
caesar = "".join(chr((ord(c) - 97 + 7) % 26 + 97) if c.islower() else c for c in F("caesar_seven"))
w("07_caesar.txt", caesar.encode(), F("caesar_seven"))

# PNG with an appended zip, whose member is gzip(base64(flag))
inner = io.BytesIO()
with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("secret.gz", gzip.compress(base64.b64encode(F("deep_chain").encode())))
w("08_trailer.png", png_bytes(Image.new("RGB", (40, 40), (10, 120, 200))) + inner.getvalue(), F("deep_chain"))

w("09_lsb.png", lsb_embed(F("lsb_hidden").encode() + b"\0" * 4), F("lsb_hidden"))
w("10_lsb_b64.png", lsb_embed(base64.b64encode(F("lsb_b64").encode()) + b"\n"), F("lsb_b64"))

# Height-reduced PNG with a correct header CRC? No: classic version keeps the old CRC.
img = Image.new("RGB", (64, 64), (255, 255, 255))
for y in range(40, 64):
    for x in range(64): img.putpixel((x, y), (0, 0, 0))
d = bytearray(png_bytes(img))
d[16 + 4:16 + 8] = struct.pack(">I", 40)  # height 64 -> 40, CRC left stale
w("11_short.png", bytes(d), None)

meta = PngImagePlugin.PngInfo()
meta.add_text("Comment", base64.b32encode(F("png_text_b32").encode()).decode())
w("12_text.png", png_bytes(Image.new("RGB", (8, 8)), pnginfo=meta), F("png_text_b32"))

ex = Image.Exif(); ex[0x010E] = F("exif_reversed")[::-1]
b = io.BytesIO(); Image.new("RGB", (16, 16), (200, 0, 0)).save(b, "JPEG", exif=ex.tobytes())
w("13_exif.jpg", b.getvalue(), F("exif_reversed"))

open("/tmp/zp_flag.txt", "w").write(base64.b64encode(F("zip_password").encode()).decode())
if os.path.exists(os.path.join(OUT, "14_locked.zip")): os.remove(os.path.join(OUT, "14_locked.zip"))
subprocess.run(["zip", "-j", "-q", "-P", "infected", os.path.join(OUT, "14_locked.zip"), "/tmp/zp_flag.txt"], check=True)
expected.append(F("zip_password"))

tb = io.BytesIO()
with tarfile.open(fileobj=tb, mode="w") as tf:
    data = b"%66%6c%61%67%7burl_encoded_tar%7d"
    ti = tarfile.TarInfo("notes/url.txt"); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
w("15_archive.tar.xz", lzma.compress(tb.getvalue()), F("url_encoded_tar"))

# pcap helpers
def pcap(packets, linktype=1):
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    for i, p in enumerate(packets):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p
    return out

def ipv4(proto, src, dst, payload):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, bytes(src), bytes(dst))
    return h + payload

def eth(ip):
    return b"\x00" * 6 + b"\x11" * 6 + b"\x08\x00" + ip

def tcp(sp, dp, seq, payload):
    return struct.pack(">HHIIBBHHH", sp, dp, seq, 0, 0x50, 0x18, 65535, 0, 0) + payload

def udp(sp, dp, payload):
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload

body = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nsecret=" + F("pcap_split").encode()
a, c = [10, 0, 0, 1], [10, 0, 0, 2]
pk = [eth(ipv4(6, c, a, tcp(80, 4444, 1000, body[:58]))),
      eth(ipv4(6, c, a, tcp(80, 4444, 1000, body[:58]))),  # retransmission
      eth(ipv4(6, c, a, tcp(80, 4444, 1058, body[58:])))]
w("16_http.pcap", pcap(pk), F("pcap_split"))

def dnsq(name):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0\0\x01\0\x01"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q
exfil = base64.b64encode(F("dns_exfil").encode()).decode()
chunks = [exfil[i:i + 8] for i in range(0, len(exfil), 8)]
w("17_dns.pcap", pcap([eth(ipv4(17, a, c, udp(5353 + i, 53, dnsq(ch + ".x.evil.com")))) for i, ch in enumerate(chunks)]), F("dns_exfil"))

# USB keyboard (USBPcap link type 249, 27-byte header)
keymap = {**{ch: (0, 4 + i) for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz")}, "{": (2, 0x2f), "}": (2, 0x30), "_": (2, 0x2d)}
reports = []
for ch in F("usb_keys"):
    mod, code = keymap[ch]
    reports += [bytes([mod, 0, code, 0, 0, 0, 0, 0]), bytes(8)]
hdr = struct.pack("<H", 27) + b"\0" * 25
w("18_usb.pcap", pcap([hdr + r for r in reports], 249), F("usb_keys"))

w("19_wide.bin", noise(64) + F("utf16_wide").encode("utf-16le") + noise(64), F("utf16_wide"))
w("20_morse.txt", b"..-. .-.. .- --. -.--. -- --- .-. ... . -.--.-", "FLAG{MORSE}")

samples = [random.randrange(-3000, 3000) for _ in range(4000)]
bits = [(byte >> (7 - i)) & 1 for byte in F("wav_lsb").encode() for i in range(8)]
for i, bt in enumerate(bits): samples[i] = (samples[i] & ~1) | bt
wb = io.BytesIO()
with wave.open(wb, "wb") as wf:
    wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(8000)
    wf.writeframes(struct.pack("<%dh" % len(samples), *samples))
w("21_audio.wav", wb.getvalue(), F("wav_lsb"))

stream = zlib.compress(b"BT /F1 12 Tf (" + F("pdf_stream").encode() + b") Tj ET")
pdf = b"%PDF-1.4\n1 0 obj<</Length " + str(len(stream)).encode() + b"/Filter/FlateDecode>>stream\n" + stream + b"\nendstream\nendobj\n%%EOF\n"
w("22_doc.pdf", pdf, F("pdf_stream"))

w("23_bz2.b64", base64.b64encode(bz2.compress(F("bzip2_inside").encode())), F("bzip2_inside"))
w("24_zstd.bin", zstandard.ZstdCompressor().compress(F("zstd_payload").encode() * 3), F("zstd_payload"))

meta = PngImagePlugin.PngInfo(); meta.add_text("note", F("xored_png"))
w("25_xored.dat", bytes(b ^ 0x42 for b in png_bytes(Image.new("RGB", (8, 8)), pnginfo=meta)), F("xored_png"))
w("26_a85.txt", b"data: " + base64.a85encode(F("ascii85").encode(), adobe=True), F("ascii85"))

def b58(b):
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return s
w("27_b58.txt", b58(F("base58_ok").encode()).encode(), F("base58_ok"))
w("28_bin.txt", " ".join(format(c, "08b") for c in F("binary_str").encode()).encode(), F("binary_str"))

zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z:
    z.writestr("in_lsb.txt", base64.b64encode(F("lsb_zip_b64").encode()))
w("29_lsb_zip.png", lsb_embed(zb.getvalue(), size=(200, 120)), F("lsb_zip_b64"))

sz = io.BytesIO()
with py7zr.SevenZipFile(sz, "w", password="hunter2") as z:
    z.writestr(F("seven_zip_pw").encode(), "f.txt")
w("30_locked.7z", sz.getvalue(), F("seven_zip_pw"))

# Nested folder + noise-only file
w("deep/nested/dir/31_reverse_b64.txt", base64.b64encode(F("reverse_then_b64").encode())[::-1], F("reverse_then_b64"))
w("deep/32_noise.bin", noise(200000), None)

# XOR'd zip with a repeating 3-byte key
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("x.txt", F("xor3_zip") * 5)
k = b"\x13\x37\x42"
w("33_xorzip.bin", bytes(b ^ k[i % 3] for i, b in enumerate(zb.getvalue())), F("xor3_zip"))

open(os.path.join(os.path.dirname(OUT.rstrip("/")), "expected.txt"), "w").write("\n".join(expected) + "\n")
print(len(expected), "flags hidden")
