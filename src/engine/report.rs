//! Render a scan result as a Markdown report for writeups.

use super::ScanResult;
use crate::config::ScanConfig;

/// CLI report: includes the targets and configured formats in the header.
pub fn markdown(cfg: &ScanConfig, paths: &[std::path::PathBuf], res: &ScanResult) -> String {
    let targets: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    let mut header = format!("- Targets: {}\n- Formats: {}\n", targets.join(", "), cfg.formats.join(", "));
    if !cfg.regex.trim().is_empty() {
        header.push_str(&format!("- Regex: `{}`\n", cfg.regex.trim()));
    }
    render(&header, res)
}

/// Server report: rendered from the result alone (no stored config).
pub fn markdown_result(res: &ScanResult) -> String {
    render("", res)
}

fn render(header: &str, res: &ScanResult) -> String {
    let mut s = String::new();
    s.push_str("# flagscan report\n\n");
    s.push_str(header);
    let st = &res.stats;
    s.push_str(&format!(
        "- Scanned {} file(s), {} layers, {:.1}s\n\n",
        st.files_total,
        st.nodes,
        st.elapsed_ms as f64 / 1000.0
    ));

    s.push_str(&format!("## Flags ({})\n\n", res.findings.len()));
    if res.findings.is_empty() {
        s.push_str("No flags found. See hints below.\n\n");
    } else {
        for f in &res.findings {
            s.push_str(&format!("### `{}`\n\n", f.flag));
            for c in &f.chains {
                s.push_str(&format!("- {}\n", c.join(" → ")));
            }
            s.push('\n');
        }
    }

    if !res.notes.is_empty() {
        s.push_str(&format!("## Hints ({})\n\n", res.notes.len()));
        for n in &res.notes {
            s.push_str(&format!("- **{}** — {}\n", escape(&n.chain.join(" › ")), escape(&n.message)));
        }
        s.push('\n');
    }

    if !res.artifacts.is_empty() {
        s.push_str(&format!("## Extracted files ({})\n\n", res.artifacts.len()));
        s.push_str("| File | Type | Size | Chain |\n|---|---|---:|---|\n");
        for a in &res.artifacts {
            s.push_str(&format!("| {} | {} | {} | {} |\n", escape(&a.name), a.kind, a.size, escape(&a.chain.join(" › "))));
        }
        s.push('\n');
    }

    if !res.triage.is_empty() {
        s.push_str("## File triage\n\n");
        s.push_str("| File | Type | Size | Entropy | SHA-256 |\n|---|---|---:|---:|---|\n");
        for t in &res.triage {
            s.push_str(&format!("| {} | {} | {} | {:.2} | `{}` |\n", escape(&t.name), t.kind, t.size, t.entropy, &t.sha256[..16]));
        }
        s.push('\n');
    }
    s
}

/// Escape the few characters that would break Markdown table cells or formatting.
fn escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}
