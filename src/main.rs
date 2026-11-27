mod config;
mod engine;
mod server;
mod update;

use clap::{Parser, Subcommand};
use config::ScanConfig;
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
        /// Save extracted artifacts (archive members, carved files, repaired images) here
        #[arg(long)]
        extract: Option<PathBuf>,
        /// Print notes (hints) as well as flags
        #[arg(short, long)]
        verbose: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
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
        Cmd::Scan { paths, formats, regex, generic, case_sensitive, depth, passwords, extract, verbose, json } => {
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
            if let Some(dir) = &extract {
                std::fs::create_dir_all(dir)?;
            }
            let res = engine::scan_blocking(&cfg, &paths, extract)?;
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
