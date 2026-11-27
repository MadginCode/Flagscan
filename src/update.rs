//! Self-update from GitHub Releases (prebuilt binaries produced by .github/workflows/release.yml).

use anyhow::Result;
use serde::Serialize;

pub const REPO_OWNER: &str = "MadginCode";
pub const REPO_NAME: &str = "Flagscan";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize, Clone, Debug)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: Option<String>,
    pub available: bool,
    pub url: Option<String>,
    pub error: Option<String>,
}

fn updater() -> Result<self_update::backends::github::Update> {
    let mut b = self_update::backends::github::Update::configure();
    b.repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name("flagscan")
        .current_version(VERSION)
        .show_download_progress(false)
        .show_output(false)
        .no_confirm(true);
    // Private repo or rate limits: honour a token if the user has one exported.
    if let Ok(t) = std::env::var("GITHUB_TOKEN").or_else(|_| std::env::var("GH_TOKEN")) {
        b.auth_token(&t);
    }
    Ok(b.build()?)
}

/// Blocking: query GitHub for a newer release.
pub fn check() -> UpdateInfo {
    let mut info = UpdateInfo { current: VERSION.into(), latest: None, available: false, url: None, error: None };
    match updater().and_then(|u| Ok(u.is_update_available()?)) {
        Ok(Some(rel)) => {
            info.latest = Some(rel.version().to_string());
            info.url = rel.release_notes_url().map(str::to_string);
            info.available = true;
        }
        Ok(None) => info.latest = Some(VERSION.into()),
        Err(e) => info.error = Some(e.to_string()),
    }
    info
}

/// Blocking: download, verify (GitHub asset digest) and replace the running binary.
/// Returns the new version if an update was installed.
pub fn apply() -> Result<Option<String>> {
    let status = updater()?.update()?;
    Ok(status.is_updated().then(|| status.version().to_string()))
}

/// Replace the current process with the freshly installed binary.
pub fn restart() -> ! {
    let _ = self_update::restart::restart();
    // If re-exec failed, exit so a supervisor (or the user) can start the new binary.
    std::process::exit(0)
}
