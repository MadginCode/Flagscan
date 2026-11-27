//! Pull files out of a reassembled TCP stream that carries HTTP/1.x. Handles chunked transfer
//! encoding, gzip/deflate bodies, and multipart/form-data uploads. Bodies are returned so the
//! scanner can recurse into them (a flag inside a downloaded image, a gzipped page, etc.).

use super::util::read_limited;

const MAX_BODIES: usize = 256;
const MAX_BODY: usize = 64 * 1024 * 1024;

pub fn extract(stream: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pos = 0;
    // A reassembled stream can hold several messages back to back (keep-alive).
    while pos < stream.len() && out.len() < MAX_BODIES {
        let Some(hdr_end) = find(&stream[pos..], b"\r\n\r\n").map(|i| pos + i + 4) else { break };
        let head = &stream[pos..hdr_end - 4];
        if !looks_http(head) {
            // Not an HTTP message boundary here; give up on this stream.
            break;
        }
        let headers = parse_headers(head);
        let (body, next) = read_body(&stream[hdr_end..], &headers);
        let consumed = hdr_end + next;

        if !body.is_empty() {
            let decoded = decode_body(&body, &headers);
            let ctype = header(&headers, "content-type").unwrap_or_default();
            if let Some(parts) = multipart(&decoded, &ctype) {
                for (i, (name, part)) in parts.into_iter().enumerate() {
                    out.push((format!("multipart part {i} {name}"), part));
                }
            } else {
                out.push((describe(&headers, &ctype), decoded));
            }
        }
        if consumed <= hdr_end - pos {
            break; // no forward progress; avoid an infinite loop
        }
        pos = consumed;
    }
    out
}

fn looks_http(head: &[u8]) -> bool {
    head.starts_with(b"HTTP/1.")
        || [b"GET ".as_slice(), b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS "]
            .iter()
            .any(|m| head.starts_with(m))
}

type Headers = Vec<(String, String)>;

fn parse_headers(head: &[u8]) -> Headers {
    let text = String::from_utf8_lossy(head);
    text.split("\r\n")
        .skip(1) // request/status line
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect()
}

fn header(h: &Headers, name: &str) -> Option<String> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
}

/// Returns the raw body and how many bytes after the header block it consumed.
fn read_body(rest: &[u8], h: &Headers) -> (Vec<u8>, usize) {
    if header(h, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        return dechunk(rest);
    }
    if let Some(len) = header(h, "content-length").and_then(|v| v.trim().parse::<usize>().ok()) {
        let n = len.min(rest.len()).min(MAX_BODY);
        return (rest[..n].to_vec(), n);
    }
    // No length given: for a response this runs to the end of the stream.
    let n = rest.len().min(MAX_BODY);
    (rest[..n].to_vec(), n)
}

fn dechunk(mut rest: &[u8]) -> (Vec<u8>, usize) {
    let total = rest.len();
    let mut out = Vec::new();
    loop {
        let Some(nl) = find(rest, b"\r\n") else { break };
        let size_line = std::str::from_utf8(&rest[..nl]).unwrap_or("");
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        let start = nl + 2;
        if size == 0 {
            rest = &rest[start..];
            break;
        }
        let end = (start + size).min(rest.len());
        out.extend_from_slice(&rest[start..end]);
        if out.len() > MAX_BODY {
            break;
        }
        // Skip the trailing CRLF after the chunk data.
        rest = &rest[(end + 2).min(rest.len())..];
    }
    (out, total - rest.len())
}

fn decode_body(body: &[u8], h: &Headers) -> Vec<u8> {
    match header(h, "content-encoding").map(|v| v.to_ascii_lowercase()) {
        Some(e) if e.contains("gzip") => read_limited(flate2::read::MultiGzDecoder::new(body), MAX_BODY).unwrap_or_else(|| body.to_vec()),
        Some(e) if e.contains("deflate") => {
            read_limited(flate2::read::ZlibDecoder::new(body), MAX_BODY)
                .or_else(|| read_limited(flate2::read::DeflateDecoder::new(body), MAX_BODY))
                .unwrap_or_else(|| body.to_vec())
        }
        _ => body.to_vec(),
    }
}

/// Split a multipart/form-data body into its parts when the content type names a boundary.
fn multipart(body: &[u8], ctype: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let b = ctype.to_ascii_lowercase();
    if !b.contains("multipart/") {
        return None;
    }
    let boundary = ctype.split("boundary=").nth(1)?.trim().trim_matches('"');
    let delim = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut search = body;
    while let Some(i) = find(search, delim.as_bytes()) {
        search = &search[i + delim.len()..];
        if search.starts_with(b"--") {
            break; // closing boundary
        }
        let Some(he) = find(search, b"\r\n\r\n") else { break };
        let name = String::from_utf8_lossy(&search[..he])
            .split("filename=")
            .nth(1)
            .and_then(|s| s.split('"').nth(1))
            .unwrap_or("part")
            .to_string();
        let after = &search[he + 4..];
        let end = find(after, format!("\r\n--{boundary}").as_bytes()).unwrap_or(after.len());
        parts.push((name, after[..end].to_vec()));
        search = &after[end..];
    }
    (!parts.is_empty()).then_some(parts)
}

fn describe(h: &Headers, ctype: &str) -> String {
    let what = if ctype.is_empty() { "body".to_string() } else { ctype.split(';').next().unwrap_or("body").trim().to_string() };
    match header(h, "content-encoding") {
        Some(e) => format!("HTTP {what} ({e})"),
        None => format!("HTTP {what}"),
    }
}

fn find(h: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(h, needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_and_plain() {
        let s = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nflag{http_body_here}";
        let out = extract(s);
        assert_eq!(out[0].1, b"flag{http_body_here}");

        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nflag\r\n5\r\n{chk}\r\n0\r\n\r\n";
        let out = extract(c);
        assert_eq!(out[0].1, b"flag{chk}");
    }
}
