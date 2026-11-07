//! credstore desktop app (M10): setup, approvals, secrets, folders, Claude Code, health.
//!
//! A thin shell around `credstore::api`: every command below forwards to it, so the
//! behaviour is tested with the rest of credstore. The app talks to the daemon like the
//! CLI does (same endpoints, a passphrase on every approver operation, nothing cached),
//! so it changes nothing in the security model. Passphrases and secret values arrive as
//! strings from the page and are wrapped in `SecretText` at once; nothing returned to
//! the page contains one.
//!
//! The window hides to the tray when closed, so approvals keep arriving. New requests
//! raise an OS notification. `--dev` talks to a dev-mode daemon.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use credstore::api::{Api, Decided, Decision, Overview, Saved};
use credstore::client::Client;
use credstore::doctor::Report;
use credstore::setup::ClaudeState;
use credstore::watch::RequestView;
use credstore_os::{Mode, Platform};
use credstore_proto::SecretText;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;

struct AppState {
    api: Api,
    /// The running subscription to pending requests, if any.
    watching: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

type CmdResult<T> = Result<T, String>;

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

fn secret(s: String) -> SecretText {
    SecretText::new(s)
}

#[tauri::command]
async fn overview(state: State<'_, AppState>) -> CmdResult<Overview> {
    Ok(state.api.overview().await)
}

#[tauri::command]
async fn create_vault(
    state: State<'_, AppState>,
    passphrase: String,
    repeat: String,
) -> CmdResult<bool> {
    state
        .api
        .create_vault(secret(passphrase), secret(repeat))
        .await
        .map_err(err)
}

#[tauri::command]
async fn set_secret(
    state: State<'_, AppState>,
    name: String,
    description: Option<String>,
    value: String,
    passphrase: String,
) -> CmdResult<Saved> {
    state
        .api
        .set_secret(&name, description, secret(value), secret(passphrase))
        .await
        .map_err(err)
}

#[tauri::command]
async fn remove_secret(
    state: State<'_, AppState>,
    name: String,
    passphrase: String,
) -> CmdResult<()> {
    state
        .api
        .remove_secret(&name, secret(passphrase))
        .await
        .map_err(err)
}

#[tauri::command]
async fn lock(state: State<'_, AppState>, passphrase: String) -> CmdResult<()> {
    state.api.lock(secret(passphrase)).await.map_err(err)
}

/// Start receiving pending requests. The page gets `pending` events with the full list
/// and a `watch-ended` event (with the reason) if the subscription stops.
#[tauri::command]
async fn start_watching(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> CmdResult<()> {
    // Check first, so a typo is reported here rather than as a dropped subscription.
    state
        .api
        .check_passphrase(secret(passphrase.clone()))
        .await
        .map_err(err)?;
    let api = state.api.clone();
    let handle = app.clone();
    let task = tauri::async_runtime::spawn(async move {
        let mut seen: HashSet<String> = HashSet::new();
        let notify = handle.clone();
        let result = api
            .watch(secret(passphrase), move |list: Vec<RequestView>| {
                for r in &list {
                    if seen.insert(r.id.clone()) {
                        let _ = notify
                            .notification()
                            .builder()
                            .title("credstore: approval needed")
                            .body(format!(
                                "{} wants {}",
                                short(&r.reason),
                                r.secrets.join(", ")
                            ))
                            .show();
                    }
                }
                seen.retain(|id| list.iter().any(|r| &r.id == id));
                let _ = notify.emit("pending", &list);
            })
            .await;
        let reason = match result {
            Ok(()) => "the subscription ended".to_owned(),
            Err(e) => format!("{e:#}"),
        };
        let _ = handle.emit("watch-ended", reason);
    });
    if let Some(old) = state.watching.lock().unwrap().replace(task) {
        old.abort();
    }
    Ok(())
}

fn short(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        out.push('…');
    }
    out
}

#[tauri::command]
async fn decide(
    state: State<'_, AppState>,
    id: String,
    decision: Decision,
    passphrase: String,
) -> CmdResult<Decided> {
    // No passphrase: confirm with Windows Hello (the UI offers this only with a key).
    if passphrase.is_empty() {
        return state
            .api
            .decide_with_hello(&id, decision)
            .await
            .map_err(err);
    }
    state
        .api
        .decide(&id, decision, secret(passphrase))
        .await
        .map_err(err)
}

/// Open the OS folder picker. `None` if the human cancelled.
#[tauri::command]
async fn pick_folder(app: AppHandle) -> CmdResult<Option<String>> {
    let picked =
        tauri::async_runtime::spawn_blocking(move || app.dialog().file().blocking_pick_folder())
            .await
            .map_err(|e| e.to_string())?;
    Ok(picked
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string()))
}

#[tauri::command]
fn grant_plan(state: State<'_, AppState>, dir: String) -> CmdResult<Vec<String>> {
    state.api.grant_plan(&PathBuf::from(dir)).map_err(err)
}

#[tauri::command]
async fn grant(state: State<'_, AppState>, dir: String) -> CmdResult<()> {
    let api = state.api.clone();
    tauri::async_runtime::spawn_blocking(move || api.grant(&PathBuf::from(dir)))
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)
}

/// `doctor` holds non-Send state across awaits, so it runs on its own small runtime.
#[tauri::command]
async fn doctor(state: State<'_, AppState>, passphrase: Option<String>) -> CmdResult<Report> {
    let api = state.api.clone();
    let pass = passphrase.filter(|p| !p.is_empty()).map(secret);
    tauri::async_runtime::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?
            .block_on(api.doctor(pass))
            .map_err(err)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn claude(state: State<'_, AppState>) -> CmdResult<Option<ClaudeState>> {
    state.api.claude().map_err(err)
}

#[tauri::command]
async fn connect_claude(state: State<'_, AppState>) -> CmdResult<ClaudeState> {
    let api = state.api.clone();
    tauri::async_runtime::spawn_blocking(move || api.connect_claude())
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)
}

/// Called by the page once it has loaded and shown the overview. With
/// `CREDSTORE_APP_SMOKE=1` (CI), the app prints what the page saw and exits.
#[tauri::command]
fn page_ready(app: AppHandle, summary: String) {
    if std::env::var_os("CREDSTORE_APP_SMOKE").is_some() {
        println!("credstore-app smoke: page ready: {summary}");
        app.exit(0);
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main() {
    let dev = std::env::args().any(|a| a == "--dev");
    let mode = if dev { Mode::Dev } else { Mode::Installed };
    let platform = match Platform::new(mode) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("credstore-app: {e}");
            std::process::exit(1);
        }
    };
    if std::env::var_os("CREDSTORE_APP_SMOKE").is_some() {
        // A page that never loads must not hang CI.
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(90));
            eprintln!("credstore-app smoke: the page did not report ready in 90 s");
            std::process::exit(2);
        });
    }
    let state = AppState {
        api: Api::new(Client::new(platform)),
        watching: Mutex::new(None),
    };
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            overview,
            create_vault,
            set_secret,
            remove_secret,
            lock,
            start_watching,
            decide,
            pick_folder,
            grant_plan,
            grant,
            doctor,
            claude,
            connect_claude,
            page_ready,
        ])
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Open credstore", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let mut tray = TrayIconBuilder::with_id("main")
                .tooltip("credstore")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            // A desktop without a tray (some Linux setups) still gets the window.
            if let Err(e) = tray.build(app) {
                eprintln!("credstore-app: no tray icon: {e}");
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing hides to the tray, so approvals keep arriving.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.app_handle().tray_by_id("main").is_some() {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("credstore-app: {e}");
        std::process::exit(1);
    }
}
