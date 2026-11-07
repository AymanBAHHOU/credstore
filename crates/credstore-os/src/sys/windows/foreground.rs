//! Keep the Windows Hello dialog in front. Hello's dialog belongs to a system broker
//! process, and Windows often opens it behind the window that asked (the app), so the
//! user sees nothing happen. While a Hello request is open, a helper thread lets other
//! processes take the foreground and brings the dialog forward when it appears.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, FindWindowW, GetForegroundWindow, SetForegroundWindow, ASFW_ANY,
};

/// Window class of the Hello dialog (Windows 10 and 11).
const DIALOG_CLASS: &str = "Credential Dialog Xaml Host";
/// The dialog is looked for this long at most.
const WATCH_FOR: Duration = Duration::from_secs(15);

/// Brings the dialog forward until dropped.
pub struct HelloInFront {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HelloInFront {
    pub fn start() -> Self {
        // SAFETY: no pointers; it only changes who may call SetForegroundWindow.
        unsafe { AllowSetForegroundWindow(ASFW_ANY) };
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let class: Vec<u16> = DIALOG_CLASS.encode_utf16().chain([0]).collect();
            let started = Instant::now();
            let mut raised = 0;
            while !flag.load(Ordering::Relaxed) && started.elapsed() < WATCH_FOR && raised < 3 {
                // SAFETY: `class` is a NUL-terminated UTF-16 string that outlives the
                // call; a null window name matches any title.
                let hwnd = unsafe { FindWindowW(class.as_ptr(), std::ptr::null()) };
                if !hwnd.is_null() {
                    // SAFETY: plain window handles; a stale one makes the calls fail.
                    unsafe {
                        if GetForegroundWindow() != hwnd {
                            SetForegroundWindow(hwnd);
                        }
                    }
                    raised += 1;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for HelloInFront {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
