# flagscan

Point it at a file or folder from a CTF and it finds the flag, even when it is buried several layers deep: a PNG with a zip appended, holding a gzip of base64 of rot13 text. Every flag is shown with the exact chain of steps that produced it, and anything the scanner extracted (archive members, carved files, repaired images) can be downloaded from the web UI.

One Rust binary, no runtime dependencies, web UI on `http://127.0.0.1:7878`, updates itself from GitHub Releases.

## Run

```sh
flagscan                       # web UI, opens your browser
flagscan scan ./challenge -f 'picoCTF{}' -v
flagscan scan dump.pcap --extract out/      # also save everything extracted
flagscan update                # install the latest release
```

`flagscan scan --help` lists all options. Settings saved in the web UI ("Save as default") also apply to the CLI; `flagscan config-path` shows where they live.

## What it looks through

Every derived blob is scanned again, so these chain in any order up to the depth limit (default 10).

| Module | Covers |
| --- | --- |
| Encodings | base64, base64url, base32, base45, base58, base62, base91, ascii85, hex (plain, `de:ad`, `\x41`, `0x41`), binary, decimal, octal, URL, HTML entities, quoted-printable, uuencode, Morse, Bacon, Brainfuck, Ook, UTF-16 LE/BE strings |
| Archives | zip (with password guessing + wordlist), tar, 7z (with password guessing + wordlist), gzip, zlib, bzip2, xz, lzma, zstd |
| Metadata | EXIF; PNG text chunks, unknown chunks, data after IEND, IHDR CRC mismatch (brute-forces the real width/height and gives you the repaired image), pixel data taller than the header; JPEG comments and data after EOI; PDF streams (FlateDecode, LZW, ASCIIHex, ASCII85, RunLength filters); OLE / compound files with VBA macro source (MS-OVBA decompressed); pcap/pcapng TCP/UDP/ICMP flows with HTTP file extraction (chunked + gzip/deflate bodies, multipart uploads) and FTP transfer hints, DNS query names (and joined first labels for exfil), USB keyboard keystrokes; repaired PNG/JPEG signatures |
| QR / barcodes | QR, Data Matrix, Aztec, PDF417 and common 1D barcodes, decoded from any image (including carved, repaired, or LSB-extracted images) |
| Embedded files | binwalk-style carving by magic bytes |
| LSB stego | zsteg-style bit planes for PNG/BMP/GIF/TIFF/WebP (R, G, B, A, RGB, BGR, RGBA; 1 and 2 bits; both bit orders; row and column order) and WAV samples |
| Ciphers | single-byte and short repeating-key XOR, Caesar (any shift), ROT13, ROT47, Atbash, and Vigenere, all recovered by known plaintext on your flag prefix (fast on big files); whole files XORed to hide a PNG/zip/PDF header; reversed data |

Flag formats: enter prefixes like `flag{}`, `CTF{`, `picoCTF`. Prefix case is ignored by default. Add a custom regex for odd formats, or turn on "Also report any word{…}" when you don't know the format (noisier).

The Hints tab lists what looked suspicious even when no flag matched: an encrypted entry the password list did not open, a resized PNG, readable text in an LSB plane, or a high-entropy file that is probably encrypted. That is usually the next step.

### Cracking, limits, and reports

- **Wordlist**: point the wordlist field (or `--wordlist rockyou.txt`) at a password list to crack encrypted zip and 7z archives. Your explicit passwords and a short built-in list are tried first, then the wordlist (capped at 1,000,000 entries).
- **Parallel scanning**: folders are scanned across worker threads (one per CPU by default; set with `--threads` or the Threads field).
- **Per-file timeout**: `--timeout <ms>` (or the Per-file timeout field) abandons any single file that takes too long and moves on, so one pathological file can't stall a folder scan.
- **Reports**: download a Markdown or JSON report from the web UI after a scan, or write one from the CLI with `--report out.md` / `--report out.json`. Every input file also gets a triage line (type, size, SHA-256, entropy).

## Auto-update

On startup the app checks the latest GitHub release of `MadginCode/Flagscan`. If it is newer, the web UI shows "Update and restart": it downloads the build for your platform, verifies the SHA-256 digest GitHub publishes for the asset, replaces the binary and restarts in place. `flagscan update` does the same from a terminal; `--no-update-check` turns the check off.

The check uses your operating system's certificate store, so it works behind TLS-inspecting corporate proxies. For a private repo, export `GITHUB_TOKEN` (or `GH_TOKEN`).

### Publishing a release

Bump `version` in `Cargo.toml` and push to `main`. If no tag exists for that version yet, `.github/workflows/release.yml` builds Linux (x86_64, arm64), macOS (Apple silicon, Intel) and Windows (x64), creates the `vX.Y.Z` tag, and publishes the release with the archives plus `SHA256SUMS`. Pushes that don't change the version publish nothing.

You can also push a tag yourself (`git tag v0.3.0 && git push --tags`); it must match the Cargo version or the workflow stops.

If you fork or rename the repo, change `REPO_OWNER` / `REPO_NAME` in `src/update.rs`.

### Code signing (optional)

The release workflow signs the macOS and Windows binaries when the matching repository secrets are set, and otherwise ships them unsigned. To enable it, add `MACOS_CERT_P12` (base64 of your `.p12`), `MACOS_CERT_PASSWORD`, `MACOS_SIGN_IDENTITY`, and for Windows `WINDOWS_CERT_PFX` (base64 of your `.pfx`) and `WINDOWS_CERT_PASSWORD`. macOS notarization (stapling) is left out; add an `xcrun notarytool` step if you need it.

## Watch mode

For a live CTF, point flagscan at your downloads folder and it scans each new or changed file as it lands, printing any flag with its decode chain:

```sh
flagscan watch ~/Downloads/ctf -f 'picoCTF{}'
```

## Build from source and tests

```sh
cargo build --release   # target/release/flagscan
```

Pure Rust apart from the TLS crypto, so it builds on Linux, macOS and Windows with a normal Rust toolchain.

`tests/make_fixtures.py` generates layered challenges hiding 45 flags (needs `pillow py7zr zstandard qrcode` and the `zip` command). CI runs the scanner over them and fails if any flag is missed.

```sh
python3 tests/make_fixtures.py target/fixtures/files
./target/release/flagscan scan target/fixtures/files
```

The parsers are fuzzed with `cargo-fuzz` (the `fuzz/` crate):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run scan
```

## Security notes

The API can read any file the user can, so the server binds to `127.0.0.1` only, rejects requests whose `Host` is not localhost (DNS rebinding), and requires a custom header on every write request (blocks cross-site form posts). Uploaded file names are sanitised so they cannot escape the temporary upload folder. Decompression is capped per blob (`max_node_size`) against zip bombs.

## Not covered

Visual stego (a flag drawn in a bit plane or spectrogram) can't be read automatically, but the web UI's **Stego tools** render every bit plane of an image and the spectrogram of a WAV so you can spot it; there's also a hex viewer on each extracted file. For anything deeper, open the file in StegSolve or Audacity. steghide/outguess-protected JPEGs need a passphrase cracker (stegseek). RAR archives are flagged but not extracted. Memory images are only string-scanned; use Volatility for real analysis.
