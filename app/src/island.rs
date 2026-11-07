//! The island: a small window at the top-centre of the screen that shows a waiting
//! request, instead of bringing the whole app forward. It appears only while a request
//! waits, can be expanded to decide (Windows Hello, or the passphrase), and goes away
//! once nothing is waiting. The idea comes from the owner's F1 Island.
//!
//! The window is borderless, transparent, always on top and kept out of the taskbar. It
//! does not take the keyboard when it appears; clicking the passphrase field gives it
//! the keyboard. The page sizes the window to its content (`island_size`), so nothing
//! around the island blocks clicks.

use tauri::{
    AppHandle, LogicalSize, Manager, Monitor, PhysicalPosition, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder,
};

pub const LABEL: &str = "island";
/// Gap between the top of the work area and the island, in logical pixels.
const GAP: f64 = 12.0;
/// Size before the page has measured itself.
const START: (f64, f64) = (460.0, 64.0);
/// Limits on what the page may ask for, so a bad message cannot cover the screen.
const MAX: (f64, f64) = (720.0, 560.0);

fn window(app: &AppHandle) -> Option<WebviewWindow> {
    app.get_webview_window(LABEL)
}

/// Show the island (creating it the first time), at the top-centre of the screen the
/// mouse is on. It does not take the keyboard.
pub fn show(app: &AppHandle) -> tauri::Result<()> {
    let win = match window(app) {
        Some(w) => w,
        None => create(app)?,
    };
    place(app, &win)?;
    if !win.is_visible()? {
        win.show()?;
    }
    Ok(())
}

fn create(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("island.html".into()))
        .title("credstore: request waiting")
        .inner_size(START.0, START.1)
        .decorations(false)
        .transparent(true)
        .shadow(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .focused(false)
        .visible(false)
        .build()
}

pub fn hide(app: &AppHandle) {
    if let Some(w) = window(app) {
        let _ = w.hide();
    }
}

/// The page measured its content: fit the window to it and keep it centred.
pub fn resize(app: &AppHandle, win: &WebviewWindow, width: f64, height: f64) -> tauri::Result<()> {
    if !(width.is_finite() && height.is_finite()) {
        return Ok(());
    }
    let w = width.clamp(120.0, MAX.0).ceil();
    let h = height.clamp(32.0, MAX.1).ceil();
    win.set_size(LogicalSize::new(w, h))?;
    place(app, win)
}

/// The screen the mouse is on, or the primary one.
fn monitor(app: &AppHandle) -> Option<Monitor> {
    app.cursor_position()
        .ok()
        .and_then(|p| app.monitor_from_point(p.x, p.y).ok().flatten())
        .or_else(|| app.primary_monitor().ok().flatten())
}

fn place(app: &AppHandle, win: &WebviewWindow) -> tauri::Result<()> {
    let Some(m) = monitor(app) else {
        return Ok(());
    };
    let area = m.work_area();
    let width = win.outer_size()?.width;
    let (x, y) = top_centre(
        area.position.x,
        area.position.y,
        area.size.width,
        width,
        (GAP * m.scale_factor()).round() as i32,
    );
    win.set_position(PhysicalPosition::new(x, y))
}

/// Where a window `width` wide goes: centred in the work area that starts at
/// (`area_x`, `area_y`) and is `area_width` wide, `gap` below its top. Physical pixels.
pub fn top_centre(area_x: i32, area_y: i32, area_width: u32, width: u32, gap: i32) -> (i32, i32) {
    let spare = i64::from(area_width) - i64::from(width);
    (area_x + (spare / 2) as i32, area_y + gap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_island_sits_at_the_top_centre() {
        assert_eq!(top_centre(0, 0, 1920, 460, 12), (730, 12));
        // A second screen to the left, and a taskbar at the top (work area starts lower).
        assert_eq!(top_centre(-2560, 48, 2560, 560, 18), (-2560 + 1000, 66));
        // Wider than the screen: still on it from the left edge's point of view.
        assert_eq!(top_centre(0, 0, 400, 460, 12), (-30, 12));
    }
}
