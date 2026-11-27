use clap::{Parser, Subcommand};
use flagscan::config::ScanConfig;
use flagscan::{engine, server, update};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "flagscan", version, about = "Scan files and folders for CTF flags through chained decoders")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the web UI (default when no command is given)
    Serve {
        #[arg(long, default_value_t = 7878)]
        port: u16,
        /// Address to bind. Keep the default unless you know why: the API reads local files.
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Do not open a browser tab
        #[arg(long)]
        no_open: bool,
        /// Do not check GitHub for a newer release on startup
        #[arg(long)]
        no_update_check: bool,
    },
    /// Scan from the terminal
    Scan {
        /// Files or folders
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Flag format, repeatable: -f flag -f 'picoCTF{}' (defaults to your saved web UI settings)
        #[arg(short, long = "format")]
        formats: Vec<String>,
        /// Extra regex to match
        #[arg(long)]
        regex: Option<String>,
        /// Also report anything shaped like word{...}
        #[arg(long)]
        generic: bool,
        /// Case-sensitive prefix matching
        #[arg(long)]
        case_sensitive: bool,
        /// Maximum chain depth
        #[arg(long)]
        depth: Option<usize>,
        /// Extra archive password to try, repeatable
        #[arg(short, long = "password")]
        passwords: Vec<String>,
        /// Wordlist file for cracking encrypted archives (e.g. rockyou.txt)
        #[arg(long)]
        wordlist: Option<PathBuf>,
        /// Abandon a single file after this many milliseconds (0 = no limit)
        #[arg(long)]
        timeout: Option<u64>,
        /// Worker threads for folder scans (0 = number of CPUs)
        #[arg(long)]
        threads: Option<usize>,
        /// Save extracted artifacts (archive members, carved files, repaired images) here
        #[arg(long)]
        extract: Option<PathBuf>,
        /// Write a report of all findings to this file (.md or .json by extension)
        #[arg(long)]
        report: Option<PathBuf>,
        /// Print notes (hints) as well as flags
        #[arg(short, long)]
        verbose: bool,
        /// JSON output to stdout
        #[arg(long)]
        json: bool,
    },
    /// Watch a folder and scan each new or changed file as it appears
    Watch {
        /// Folder to watch
        dir: PathBuf,
        /// Flag format, repeatable
        #[arg(short, long = "format")]
        formats: Vec<String>,
        /// Poll interval in seconds
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// Download and install the latest release from GitHub
    Update,
    /// Print where settings are stored
    ConfigPath,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Serve { port: 7878, bind: "127.0.0.1".into(), no_open: false, no_update_check: false }) {
        Cmd::Serve { port, bind, no_open, no_update_check } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::serve(server::ServeOpts { bind, port, open: !no_open, update_check: !no_update_check }))
        }
        Cmd::Scan { paths, formats, regex, generic, case_sensitive, depth, passwords, wordlist, timeout, threads, extract, report, verbose, json } => {
            let mut cfg = ScanConfig::load();
            if !formats.is_empty() {
                cfg.formats = formats;
            }
            if let Some(r) = regex {
                cfg.regex = r;
            }
            cfg.generic |= generic;
            if case_sensitive {
                cfg.case_insensitive = false;
            }
            if let Some(d) = depth {
                cfg.max_depth = d;
            }
            cfg.passwords.extend(passwords);
            if let Some(w) = wordlist {
                cfg.wordlist = w.to_string_lossy().into_owned();
            }
            if let Some(t) = timeout {
                cfg.file_timeout_ms = t;
            }
            if let Some(t) = threads {
                cfg.threads = t;
            }
            if let Some(dir) = &extract {
                std::fs::create_dir_all(dir)?;
            }
            let res = engine::scan_blocking(&cfg, &paths, extract)?;
            if let Some(path) = &report {
                let is_json = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("json"));
                let body = if is_json { serde_json::to_string_pretty(&res)? } else { engine::report::markdown(&cfg, &paths, &res) };
                std::fs::write(path, body)?;
                eprintln!("report written to {}", path.display());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&res)?);
                return Ok(());
            }
            if res.findings.is_empty() {
                println!("no flags found ({} blobs examined)", res.stats.nodes);
            }
            for f in &res.findings {
                println!("{}", f.flag);
                for c in &f.chains {
                    println!("    via {}", c.join(" -> "));
                }
            }
            if verbose {
                for n in &res.notes {
                    println!("note: [{}] {}", n.chain.join(" -> "), n.message);
                }
                for a in &res.artifacts {
                    println!("artifact: {} ({} bytes) {}", a.name, a.size, a.chain.join(" -> "));
                }
            } else if !res.notes.is_empty() {
                println!("({} notes, run with -v to see them)", res.notes.len());
            }
            Ok(())
        }
        Cmd::Watch { dir, formats, interval } => {
            let mut cfg = ScanConfig::load();
            if !formats.is_empty() {
                cfg.formats = formats;
            }
            if !dir.is_dir() {
                anyhow::bail!("{} is not a folder", dir.display());
            }
            println!("watching {} (Ctrl-C to stop)", dir.display());
            let mut seen: std::collections::HashMap<PathBuf, (u64, std::time::SystemTime)> = std::collections::HashMap::new();
            let mut flags_shown: std::collections::HashSet<String> = std::collections::HashSet::new();
            loop {
                let mut fresh = Vec::new();
                for e in walkdir::WalkDir::new(&dir).into_iter().flatten() {
                    if !e.file_type().is_file() {
                        continue;
                    }
                    if let Ok(m) = e.metadata() {
                        let key = (m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH));
                        if seen.get(e.path()) != Some(&key) {
                            seen.insert(e.path().to_path_buf(), key);
                            fresh.push(e.path().to_path_buf());
                        }
                    }
                }
                if !fresh.is_empty() {
                    if let Ok(res) = engine::scan_blocking(&cfg, &fresh, None) {
                        for f in &res.findings {
                            if flags_shown.insert(f.flag.clone()) {
                                println!("{}  [{}]", f.flag, f.chains[0].join(" -> "));
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
            }
        }
        Cmd::Update => {
            let info = update::check();
            if let Some(e) = info.error {
                anyhow::bail!("update check failed: {e}");
            }
            if !info.available {
                println!("flagscan v{} is up to date", info.current);
                return Ok(());
            }
            match update::apply()? {
                Some(v) => println!("updated to v{v}"),
                None => println!("already up to date"),
            }
            Ok(())
        }
        Cmd::ConfigPath => {
            println!("{}", ScanConfig::path().map(|p| p.display().to_string()).unwrap_or_else(|| "(none)".into()));
            Ok(())
        }
    }
}
