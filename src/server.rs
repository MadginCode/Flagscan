//! Local web UI + JSON API.

use crate::config::{FlagMatcher, ScanConfig};
use crate::engine::{Job, ScanResult};
use crate::update::{self, UpdateInfo};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path as AxPath, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::AsyncWriteExt;

const INDEX: &str = include_str!("../ui/index.html");
const MAX_JOBS: usize = 16;

struct JobEntry {
    job: Arc<Job>,
    _artifacts: tempfile::TempDir,
    _uploads: Option<tempfile::TempDir>,
    created: Instant,
}

pub struct AppState {
    jobs: Mutex<HashMap<String, JobEntry>>,
    config: Mutex<ScanConfig>,
    update: Mutex<Option<UpdateInfo>>,
    allowed_hosts: Vec<String>,
}

type S = State<Arc<AppState>>;

pub struct ServeOpts {
    pub bind: String,
    pub port: u16,
    pub open: bool,
    pub update_check: bool,
}

pub async fn serve(opts: ServeOpts) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", opts.bind, opts.port).parse()?;
    let loopback = addr.ip().is_loopback();
    let mut allowed_hosts = vec![];
    if loopback {
        for h in ["127.0.0.1", "localhost", "[::1]"] {
            allowed_hosts.push(format!("{h}:{}", opts.port));
        }
    }
    let state = Arc::new(AppState {
        jobs: Mutex::new(HashMap::new()),
        config: Mutex::new(ScanConfig::load()),
        update: Mutex::new(None),
        allowed_hosts,
    });

    if opts.update_check {
        let st = state.clone();
        tokio::task::spawn_blocking(move || {
            let info = update::check();
            if info.available {
                eprintln!("update available: v{} -> v{} (open the web UI or run `flagscan update`)", info.current, info.latest.clone().unwrap_or_default());
            }
            *st.update.lock().unwrap() = Some(info);
        });
    }

    let app = Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/scan", post(scan_paths))
        .route("/api/upload", post(upload).layer(DefaultBodyLimit::disable()))
        .route("/api/jobs/{id}", get(job_status))
        .route("/api/jobs/{id}/cancel", post(job_cancel))
        .route("/api/jobs/{id}/artifacts/{aid}", get(artifact))
        .route("/api/jobs/{id}/report", get(report))
        .route("/api/update", get(update_status).post(update_apply))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state);

    // Retry binding for a few seconds: after a self-update restart the old socket may linger.
    let mut tries = 0;
    let listener = loop {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => break l,
            Err(e) if tries < 25 => {
                tries += 1;
                if tries == 1 {
                    eprintln!("waiting for {addr}: {e}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    let shown = if loopback { format!("http://127.0.0.1:{}", opts.port) } else { format!("http://{addr}") };
    println!("flagscan v{} listening on {shown}", update::VERSION);
    if !loopback {
        eprintln!("warning: bound to a non-loopback address; anyone who can reach it can read files on this machine through the scan API");
    }
    if opts.open {
        let _ = webbrowser::open(&shown);
    }
    axum::serve(listener, app).await?;
    Ok(())
}

/// Blocks DNS-rebinding (Host check) and cross-site form posts (custom header forces a CORS
/// preflight, which we never answer), since this API can read any local path.
async fn guard(State(st): S, req: Request, next: Next) -> Response {
    if !st.allowed_hosts.is_empty() {
        let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
        if !st.allowed_hosts.iter().any(|a| a == host) {
            return (StatusCode::FORBIDDEN, "bad host").into_response();
        }
    }
    if req.method() != Method::GET && req.headers().get("x-flagscan").is_none() {
        return (StatusCode::FORBIDDEN, "missing x-flagscan header").into_response();
    }
    next.run(req).await
}

fn err(code: StatusCode, msg: impl ToString) -> Response {
    (code, Json(serde_json::json!({ "error": msg.to_string() }))).into_response()
}

async fn get_config(State(st): S) -> Json<serde_json::Value> {
    let cfg = st.config.lock().unwrap().clone();
    Json(serde_json::json!({ "config": cfg, "defaults": ScanConfig::default(), "version": update::VERSION }))
}

async fn put_config(State(st): S, Json(cfg): Json<ScanConfig>) -> Response {
    if let Err(e) = FlagMatcher::new(&cfg) {
        return err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    let _ = cfg.save();
    *st.config.lock().unwrap() = cfg;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct ScanReq {
    paths: Vec<String>,
    config: Option<ScanConfig>,
}

fn new_job(st: &AppState, cfg: ScanConfig, paths: Vec<PathBuf>, uploads: Option<tempfile::TempDir>) -> Result<String, Response> {
    let matcher = FlagMatcher::new(&cfg).map_err(|e| err(StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    let artifacts = tempfile::Builder::new().prefix("flagscan-art-").tempdir().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let job = Job::with_passwords(Some(artifacts.path().to_path_buf()), cfg.all_passwords());
    let id = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
    let root = uploads.as_ref().map(|u| u.path().to_path_buf());
    {
        let mut jobs = st.jobs.lock().unwrap();
        while jobs.len() >= MAX_JOBS {
            let oldest = jobs.iter().min_by_key(|(_, j)| j.created).map(|(k, _)| k.clone()).unwrap();
            if let Some(j) = jobs.remove(&oldest) {
                j.job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        jobs.insert(id.clone(), JobEntry { job: job.clone(), _artifacts: artifacts, _uploads: uploads, created: Instant::now() });
    }
    tokio::task::spawn_blocking(move || {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::engine::run(&cfg, &matcher, &job, &paths, root.as_deref());
        }));
        if r.is_err() {
            let mut res = job.result.lock().unwrap();
            res.stats.state = "error".into();
            res.stats.error = Some("internal error while scanning (see terminal)".into());
        }
    });
    Ok(id)
}

async fn scan_paths(State(st): S, Json(req): Json<ScanReq>) -> Response {
    let cfg = req.config.unwrap_or_else(|| st.config.lock().unwrap().clone());
    let mut paths = vec![];
    for p in req.paths.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let p = expand_tilde(p);
        if !p.exists() {
            return err(StatusCode::BAD_REQUEST, format!("path not found: {}", p.display()));
        }
        paths.push(p);
    }
    if paths.is_empty() {
        return err(StatusCode::BAD_REQUEST, "no path given");
    }
    match new_job(&st, cfg, paths, None) {
        Ok(id) => Json(serde_json::json!({ "job": id })).into_response(),
        Err(r) => r,
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\"))
        && let Some(h) = dirs::home_dir() {
            return h.join(rest);
        }
    PathBuf::from(p.trim_matches('"'))
}

/// Keep only normal components so uploaded names cannot escape the upload dir.
fn safe_rel(name: &str) -> Option<PathBuf> {
    let p: PathBuf = PathBuf::from(name.replace('\\', "/"))
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_owned()),
            _ => None,
        })
        .collect();
    (!p.as_os_str().is_empty()).then_some(p)
}

async fn upload(State(st): S, mut mp: Multipart) -> Response {
    let dir = match tempfile::Builder::new().prefix("flagscan-up-").tempdir() {
        Ok(d) => d,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let mut cfg = st.config.lock().unwrap().clone();
    let mut n = 0;
    loop {
        let mut field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return err(StatusCode::BAD_REQUEST, e),
        };
        if field.name() == Some("config") {
            match field.text().await.ok().and_then(|t| serde_json::from_str(&t).ok()) {
                Some(c) => cfg = c,
                None => return err(StatusCode::BAD_REQUEST, "bad config json"),
            }
            continue;
        }
        let name = field.file_name().map(str::to_string).unwrap_or_else(|| format!("upload{n}"));
        let Some(rel) = safe_rel(&name) else { continue };
        let path = dir.path().join(rel);
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let Ok(mut f) = tokio::fs::File::create(&path).await else { continue };
        loop {
            match field.chunk().await {
                Ok(Some(c)) => {
                    if f.write_all(&c).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => return err(StatusCode::BAD_REQUEST, e),
            }
        }
        n += 1;
    }
    if n == 0 {
        return err(StatusCode::BAD_REQUEST, "no files received");
    }
    let root = dir.path().to_path_buf();
    match new_job(&st, cfg, vec![root], Some(dir)) {
        Ok(id) => Json(serde_json::json!({ "job": id, "files": n })).into_response(),
        Err(r) => r,
    }
}

async fn job_status(State(st): S, AxPath(id): AxPath<String>) -> Response {
    let job = st.jobs.lock().unwrap().get(&id).map(|j| j.job.clone());
    match job {
        Some(j) => {
            let snap: ScanResult = j.snapshot();
            Json(snap).into_response()
        }
        None => err(StatusCode::NOT_FOUND, "unknown job"),
    }
}

async fn job_cancel(State(st): S, AxPath(id): AxPath<String>) -> Response {
    if let Some(j) = st.jobs.lock().unwrap().get(&id) {
        j.job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn artifact(State(st): S, AxPath((id, aid)): AxPath<(String, usize)>) -> Response {
    let job = st.jobs.lock().unwrap().get(&id).map(|j| j.job.clone());
    let Some(job) = job else { return err(StatusCode::NOT_FOUND, "unknown job") };
    let info = job.result.lock().unwrap().artifacts.get(aid).cloned();
    let Some(info) = info else { return err(StatusCode::NOT_FOUND, "unknown artifact") };
    match tokio::fs::read(&info.path).await {
        Ok(bytes) => {
            let mut h = HeaderMap::new();
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", info.name)) {
                h.insert(header::CONTENT_DISPOSITION, v);
            }
            (h, Body::from(bytes)).into_response()
        }
        Err(e) => err(StatusCode::NOT_FOUND, e),
    }
}

async fn report(State(st): S, AxPath(id): AxPath<String>, req: Request) -> Response {
    let job = st.jobs.lock().unwrap().get(&id).map(|j| j.job.clone());
    let Some(job) = job else { return err(StatusCode::NOT_FOUND, "unknown job") };
    let res = job.snapshot();
    let json = req.uri().query().is_some_and(|q| q.contains("json"));
    let (body, ctype, fname) = if json {
        (serde_json::to_string_pretty(&res).unwrap_or_default(), "application/json", "flagscan-report.json")
    } else {
        (crate::engine::report::markdown_result(&res), "text/markdown; charset=utf-8", "flagscan-report.md")
    };
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{fname}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    (h, body).into_response()
}

async fn update_status(State(st): S, req: Request) -> Response {
    let refresh = req.uri().query().is_some_and(|q| q.contains("refresh"));
    let cached = st.update.lock().unwrap().clone();
    if let (Some(info), false) = (cached, refresh) {
        return Json(info).into_response();
    }
    let info = tokio::task::spawn_blocking(update::check).await.unwrap_or_else(|_| UpdateInfo {
        current: update::VERSION.into(),
        latest: None,
        available: false,
        url: None,
        error: Some("update check failed".into()),
    });
    *st.update.lock().unwrap() = Some(info.clone());
    Json(info).into_response()
}

async fn update_apply(State(_st): S) -> Response {
    match tokio::task::spawn_blocking(update::apply).await {
        Ok(Ok(Some(v))) => {
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                update::restart();
            });
            Json(serde_json::json!({ "updated": true, "version": v })).into_response()
        }
        Ok(Ok(None)) => Json(serde_json::json!({ "updated": false })).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_GATEWAY, format!("{e:#}")),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
