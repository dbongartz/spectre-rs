//! Copies passwords to the system clipboard and wipes them again after a while.

use std::time::{Duration, Instant};

use secstr::SecStr;

/// The system clipboard, holding at most one password at a time.
///
/// Uses `arboard` directly rather than egui's clipboard, for two things egui can't do: read the
/// clipboard back, so a wipe never destroys something the user copied afterwards, and mark the
/// password as secret, so clipboard managers leave it out of their history.
pub struct PasswordClipboard {
    /// `None` if the system clipboard is unavailable; egui's clipboard is used instead.
    system: Option<arboard::Clipboard>,
    copied: Option<Copied>,
}

struct Copied {
    password: SecStr,
    clear_at: Instant,
}

impl PasswordClipboard {
    pub fn new() -> Self {
        let system = arboard::Clipboard::new()
            .inspect_err(|error| {
                log::warn!("System clipboard unavailable, using egui's instead: {error}");
            })
            .ok();
        Self {
            system,
            copied: None,
        }
    }

    /// Puts `password` on the clipboard, to be wiped after `clear_after`.
    pub fn copy(&mut self, ctx: &egui::Context, password: &str, clear_after: Duration) {
        let copied_to_system = self.system.as_mut().is_some_and(|clipboard| {
            set_secret_text(clipboard, password)
                .inspect_err(|error| log::warn!("Failed to copy to the system clipboard: {error}"))
                .is_ok()
        });
        if !copied_to_system {
            ctx.copy_text(password.to_owned());
        }
        self.copied = Some(Copied {
            password: SecStr::from(password),
            clear_at: Instant::now() + clear_after,
        });
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    /// Wipes the password once it is due, and schedules repaints for the countdown until then.
    pub fn clear_when_due(&mut self, ctx: &egui::Context) {
        let Some(copied) = &self.copied else {
            return;
        };
        let now = Instant::now();
        if now >= copied.clear_at {
            self.clear(ctx);
        } else {
            // Repaint each second for the countdown, and exactly when the wipe is due.
            ctx.request_repaint_after((copied.clear_at - now).min(Duration::from_secs(1)));
        }
    }

    /// Wipes the password now, if it is still on the clipboard.
    pub fn clear(&mut self, ctx: &egui::Context) {
        let Some(copied) = self.copied.take() else {
            return;
        };
        match &mut self.system {
            Some(clipboard) => clear_if_unchanged(clipboard, &copied.password),
            // egui can't read the clipboard back, so it can only wipe it unconditionally.
            None => ctx.copy_text(String::new()),
        }
    }

    /// Wipes the password on shutdown, where there is no egui context left to fall back on.
    pub fn clear_on_exit(&mut self) {
        if let (Some(copied), Some(clipboard)) = (self.copied.take(), &mut self.system) {
            clear_if_unchanged(clipboard, &copied.password);
        }
    }

    /// The time left until the clipboard is wiped, while a password is on it.
    pub fn remaining(&self) -> Option<Duration> {
        let copied = self.copied.as_ref()?;
        Some(copied.clear_at.saturating_duration_since(Instant::now()))
    }
}

fn set_secret_text(clipboard: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    let set = clipboard.set();
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "windows"
    ))]
    let set = {
        #[cfg(not(target_os = "windows"))]
        use arboard::SetExtLinux as _;
        #[cfg(target_os = "windows")]
        use arboard::SetExtWindows as _;
        set.exclude_from_history()
    };
    set.text(text)
}

/// Clears the clipboard, unless it no longer holds `password` because something else was copied.
fn clear_if_unchanged(clipboard: &mut arboard::Clipboard, password: &SecStr) {
    let unchanged = clipboard
        .get_text()
        .is_ok_and(|text| SecStr::from(text) == *password);
    if unchanged && let Err(error) = clipboard.clear() {
        log::warn!("Failed to clear the clipboard: {error}");
    }
}
