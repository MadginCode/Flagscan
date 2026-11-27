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
| Encodings | base64, base64url, base32, base58, ascii85, hex (plain, `de:ad`, `\x41`, `0x41`), binary, decimal, octal, URL, HTML entities, Morse, UTF-16 LE/BE strings |
| Archives | zip (with password guessing), tar, 7z (with password guessing), gzip, zlib, bzip2, xz, lzma, zstd |
| Metadata | EXIF; PNG text chunks, unknown chunks, data after IEND, IHDR CRC mismatch (brute-forces the real width/height and gives you the repaired image), pixel data taller than the header; JPEG comments and data after EOI; PDF streams; pcap/pcapng TCP/UDP/ICMP flows, DNS query names (and joined first labels for exfil), USB keyboard keystrokes; repaired PNG/JPEG signatures |
| Embedded files | binwalk-style carving by magic bytes |
| LSB stego | zsteg-style bit planes for PNG/BMP/GIF/TIFF/WebP (R, G, B, A, RGB, BGR, RGBA; 1 and 2 bits; both bit orders; row and column order) and WAV samples |
| XOR | single-byte and short repeating keys, found by known plaintext on your flag prefix (fast on big files); whole files XORed to hide a PNG/zip/PDF header |
| ROT / reverse | Caesar (any shift), ROT13, ROT47, Atbash, reversed data |

Flag formats: enter prefixes like `flag{}`, `CTF{`, `picoCTF`. Prefix case is ignored by default. Add a custom regex for odd formats, or turn on "Also report any word{…}" when you don't know the format (noisier).

The Hints tab lists what looked suspicious even when no flag matched: an encrypted entry the password list did not open, a resized PNG, readable text in an LSB plane. That is usually the next step.

## Auto-update

On startup the app checks the latest GitHub release of `MadginCode/Flagscan`. If it is newer, the web UI shows "Update and restart": it downloads the build for your platform, verifies the SHA-256 digest GitHub publishes for the asset, replaces the binary and restarts in place. `flagscan update` does the same from a terminal; `--no-update-check` turns the check off.

The check uses your operating system's certificate store, so it works behind TLS-inspecting corporate proxies. For a private repo, export `GITHUB_TOKEN` (or `GH_TOKEN`).

### Publishing a release

1. Bump `version` in `Cargo.toml`, commit.
2. `git tag v0.2.0 && git push --tags`

`.github/workflows/release.yml` builds Linux (x86_64, arm64), macOS (Apple silicon, Intel) and Windows (x64), and attaches the archives plus `SHA256SUMS` to the release. The tag must match the Cargo version or the workflow stops.

If you fork or rename the repo, change `REPO_OWNER` / `REPO_NAME` in `src/update.rs`.

## Build from source

```sh
cargo build --release   # target/release/flagscan
```

Pure Rust apart from the TLS crypto, so it builds on Linux, macOS and Windows with a normal Rust toolchain.

## Tests

`tests/make_fixtures.py` generates layered challenges hiding 31 flags (needs `pillow py7zr zstandard` and the `zip` command). CI runs the scanner over them and fails if any flag is missed.

```sh
python3 tests/make_fixtures.py target/fixtures/files
./target/release/flagscan scan target/fixtures/files
```

## Security notes

The API can read any file the user can, so the server binds to `127.0.0.1` only, rejects requests whose `Host` is not localhost (DNS rebinding), and requires a custom header on every write request (blocks cross-site form posts). Uploaded file names are sanitised so they cannot escape the temporary upload folder. Decompression is capped per blob (`max_node_size`) against zip bombs.

## Not covered

Visual stego (a flag drawn in a bit plane or spectrogram) needs eyes: open the file in StegSolve or Audacity. steghide/outguess-protected JPEGs need a passphrase cracker (stegseek). RAR archives are flagged but not extracted. Memory images are only string-scanned; use Volatility for real analysis.
