//! Fit the main window to the screen it opens on. The configured size (1180 x 780) is
//! taller than the usable area of many laptops (a 1366 x 768 screen, or 1920 x 1080 at
//! 150 % scaling), which left the bottom of the window under the taskbar.

use tauri::{PhysicalPosition, PhysicalSize, WebviewWindow};

/// Room left around the window, as a share of the work area.
const MARGIN: f64 = 0.04;

/// Shrink `win` to fit the work area of its screen (the screen minus the taskbar) and
/// centre it there. A window that already fits only gets centred.
pub fn fit_to_screen(win: &WebviewWindow) -> tauri::Result<()> {
    let monitor = match win.current_monitor()? {
        Some(m) => m,
        None => match win.primary_monitor()? {
            Some(m) => m,
            None => return Ok(()),
        },
    };
    let area = monitor.work_area();
    let size = win.outer_size()?;
    let (x, y, w, h) = place(
        (area.position.x, area.position.y),
        (area.size.width, area.size.height),
        (size.width, size.height),
    );
    if (w, h) != (size.width, size.height) {
        win.set_size(PhysicalSize::new(w, h))?;
    }
    win.set_position(PhysicalPosition::new(x, y))
}

/// Position and size (physical pixels) for a window of `size` in the work area at
/// `origin` of `area`: at most the area minus a margin on each side, centred.
pub fn place(origin: (i32, i32), area: (u32, u32), size: (u32, u32)) -> (i32, i32, u32, u32) {
    let fit = |want: u32, room: u32| {
        let max = (f64::from(room) * (1.0 - 2.0 * MARGIN)).floor() as u32;
        want.min(max.max(1))
    };
    let (w, h) = (fit(size.0, area.0), fit(size.1, area.1));
    let x = origin.0 + ((i64::from(area.0) - i64::from(w)) / 2) as i32;
    let y = origin.1 + ((i64::from(area.1) - i64::from(h)) / 2) as i32;
    (x, y, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_that_fits_is_only_centred() {
        // 1180 x 780 on a 1920 x 1040 work area (1080p, taskbar at the bottom).
        assert_eq!(
            place((0, 0), (1920, 1040), (1180, 780)),
            (370, 130, 1180, 780)
        );
    }

    #[test]
    fn a_tall_window_shrinks_to_the_work_area() {
        // 1080p at 150 %: 1770 x 1170 physical for the window, 1920 x 1032 to use. Both
        // sides shrink to leave the margin.
        let (x, y, w, h) = place((0, 0), (1920, 1032), (1770, 1170));
        assert_eq!((w, h), (1766, 949));
        assert_eq!((x, y), (77, 41));
        assert!(y + h as i32 <= 1032, "the bottom stays above the taskbar");
    }

    #[test]
    fn a_second_screen_and_a_top_taskbar_move_the_origin() {
        let (x, y, w, h) = place((-1366, 40), (1366, 728), (1180, 780));
        assert_eq!((w, h), (1180, 669));
        assert_eq!((x, y), (-1366 + 93, 40 + 29));
    }
}
