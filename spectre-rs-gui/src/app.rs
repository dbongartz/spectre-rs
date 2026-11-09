//! The app: its state, and the form and password it shows.

use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use egui::{Color32, RichText};
use secstr::{SecStr, SecUtf8};
use spectre_rs_core::{PwType, SpectreError, identicon::Identicon};
use zeroize::Zeroize;

use crate::clipboard::PasswordClipboard;
use crate::derive::{self, DeriveRequest, DerivedKey};
use crate::theme::{
    self, ACCENT_ACTIVE_COLOR, ACCENT_COLOR, ACCENT_HOVER_COLOR, ACCENT_TEXT_COLOR, CHIP_COLOR,
    COPIED_COLOR, COPIED_TEXT_COLOR, COPY_BUTTON_WIDTH, CORNER_RADIUS, DEFAULT_ZOOM, FIELD_GAP,
    FIELD_HEIGHT, FIELD_PADDING, FIELD_WIDTH, HIGHLIGHT_INSET, HIGHLIGHT_RADIUS, HINT_SIZE,
    ICON_COLOR, ICON_SIZE, IDENTICON_CHIP_MIN_WIDTH, IDENTICON_SIZE, INACTIVE_PASSWORD_COLOR,
    LABEL_WIDTH, MUTED_TEXT_COLOR, PASSWORD_COLOR, PASSWORD_MARGIN, PASSWORD_SIZE, ROW_GAP,
    SECRET_TRAILING_WIDTH, TEXT_COLOR, TEXT_SIZE, TYPE_WIDTH, VERSION_COLOR, WINDOW_SIZE,
};
use crate::widgets::{
    counter_stepper, focus_ring, forget_undo_history, icon_button, password_type_selector,
    row_icon, submitted, text_field,
};
use crate::{APP_TITLE, fonts};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
/// How long a stale password may show at full contrast while its replacement is derived.
const STALE_DIM_DELAY: Duration = Duration::from_millis(250);
/// How long the copy button reads "Copied".
const COPIED_FEEDBACK: Duration = Duration::from_secs(2);
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const USER_NAME_KEY: &str = "user_name";
/// Room for the secret before the field has to reallocate, leaving an unwiped copy behind.
const SECRET_CAPACITY: usize = 256;

pub struct App {
    input: Input,
    derive_tx: mpsc::Sender<DeriveRequest>,
    derived_rx: mpsc::Receiver<DerivedKey>,
    derivation_revision: u64,
    user_key: Option<SecStr>,
    site_password: Option<SecUtf8>,
    identicon: String,
    identicon_color: Color32,
    show_secret: bool,
    /// Set when Enter is pressed in a field this frame; copies the password if there is one.
    copy_requested: bool,
    /// When the pending user-key derivation started; `None` once the key is current.
    deriving_since: Option<Instant>,
    /// A copy asked for while deriving; done once the new password is ready.
    copy_pending: bool,
    copied_at: Option<Instant>,
    clipboard: PasswordClipboard,
    /// The window size when a resize was last requested; see [`App::keep_window_size`].
    resize_requested_at: Option<egui::Vec2>,
}

struct Input {
    user_name: String,
    user_secret: String,
    site_name: String,
    pw_type: PwType,
    counter: u32,
}

impl Default for Input {
    fn default() -> Self {
        Self {
            user_name: String::new(),
            user_secret: String::with_capacity(SECRET_CAPACITY),
            site_name: String::new(),
            pw_type: PwType::Medium,
            counter: 1,
        }
    }
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("user_name", &self.user_name)
            .field("user_secret", &"***SECRET***")
            .field("site_name", &self.site_name)
            .field("pw_type", &self.pw_type)
            .field("counter", &self.counter)
            .finish()
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        self.user_secret.zeroize();
    }
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let saved_user_name = cc
            .storage
            .and_then(|storage| eframe::get_value::<String>(storage, USER_NAME_KEY));
        // Nothing saved yet means this is the first launch. Later launches keep the zoom the
        // user chose, which egui restores on its own.
        if saved_user_name.is_none() {
            cc.egui_ctx.set_zoom_factor(DEFAULT_ZOOM);
        }
        theme::apply(&cc.egui_ctx);
        fonts::install(&cc.egui_ctx);

        let mut input = Input::default();
        input.user_name = saved_user_name.unwrap_or_default();
        let (derive_tx, derived_rx) = derive::start(cc.egui_ctx.clone());

        Self {
            input,
            derive_tx,
            derived_rx,
            derivation_revision: 0,
            user_key: None,
            site_password: None,
            identicon: String::new(),
            identicon_color: Color32::WHITE,
            show_secret: false,
            copy_requested: false,
            deriving_since: None,
            copy_pending: false,
            copied_at: None,
            clipboard: PasswordClipboard::new(),
            resize_requested_at: None,
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.keep_window_size(ui.ctx());
        self.receive_derived_keys(ui.ctx());
        self.clipboard.clear_when_due(ui.ctx());
        self.copy_requested = false;
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                self.show_form(ui);
                self.show_password(ui);
            });
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Max), |ui| {
                ui.label(
                    RichText::new(format!("v{APP_VERSION}"))
                        .size(HINT_SIZE - 1.0)
                        .color(VERSION_COLOR),
                )
                .on_hover_text(APP_TITLE);
            });
        });
        // Checked after the widgets ran, so a selection they copied this frame takes precedence.
        if self.copy_shortcut_pressed(ui.ctx()) {
            self.copy_password(ui.ctx());
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, USER_NAME_KEY, &self.input.user_name);
    }

    fn on_exit(&mut self) {
        self.clipboard.clear_on_exit();
    }
}

impl App {
    /// Keeps the window at [`WINDOW_SIZE`] points, so it grows and shrinks with the zoom
    /// instead of reflowing the fixed layout.
    ///
    /// Asks again only once the size has changed since the last request: requests made before
    /// the window is mapped get lost and must be repeated, but a window manager that won't
    /// resize the window (a tiling one, say) mustn't be asked on every frame.
    fn keep_window_size(&mut self, ctx: &egui::Context) {
        let size = ctx.viewport_rect().size();
        if (size - WINDOW_SIZE).abs().max_elem() > 0.5 && self.resize_requested_at != Some(size) {
            self.resize_requested_at = Some(size);
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(WINDOW_SIZE));
        }
    }

    fn receive_derived_keys(&mut self, ctx: &egui::Context) {
        while let Ok(derived) = self.derived_rx.try_recv() {
            if derived.revision != self.derivation_revision {
                continue;
            }
            self.deriving_since = None;

            match derived.user_key {
                Ok(user_key) => {
                    self.user_key = user_key;
                    if let Err(error) = self.update_site_password() {
                        log::error!("Failed to generate site password: {error}");
                        self.site_password = None;
                    }
                }
                Err(error) => {
                    log::error!("Failed to derive user key: {error}");
                    self.user_key = None;
                    self.site_password = None;
                }
            }
            if std::mem::take(&mut self.copy_pending) {
                self.copy_password(ctx);
            }
        }
    }

    fn show_form(&mut self, ui: &mut egui::Ui) {
        let form_width = LABEL_WIDTH + FIELD_GAP + FIELD_WIDTH;
        let field_width = FIELD_WIDTH.min(ui.available_width() - LABEL_WIDTH - FIELD_GAP);

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - form_width) * 0.5).max(0.0));
            egui::Grid::new("form_fields")
                .num_columns(2)
                .min_col_width(LABEL_WIDTH)
                .spacing([FIELD_GAP, ROW_GAP])
                .show(ui, |ui| {
                    let credentials_changed = self.show_credential_fields(ui, field_width);
                    let site_changed = self.show_site_fields(ui, field_width);
                    self.handle_input_changes(credentials_changed, site_changed);
                });
        });
    }

    fn show_credential_fields(&mut self, ui: &mut egui::Ui, field_width: f32) -> bool {
        let icon = row_icon(
            ui,
            "\u{f007}",
            "User",
            "Name used to derive your passwords. Keep it consistent across devices.",
        );
        let user_name = ui
            .add_sized(
                [field_width, FIELD_HEIGHT],
                text_field(&mut self.input.user_name, "User"),
            )
            .labelled_by(icon.id);
        self.copy_requested |= submitted(&user_name);
        ui.end_row();

        let icon = row_icon(
            ui,
            "\u{f084}",
            "Secret",
            "Your master secret, used locally to derive your account key.",
        );
        let secret = self.show_secret_field(ui, field_width).labelled_by(icon.id);
        self.copy_requested |= submitted(&secret);
        ui.end_row();

        user_name.changed() || secret.changed()
    }

    /// The secret field, with the identicon chip and the show/hide toggle inside it.
    ///
    /// The text edit only covers the left part of the field, so the toggle beside it gets its
    /// clicks; the field background and focus outline are painted across the whole width.
    fn show_secret_field(&mut self, ui: &mut egui::Ui, field_width: f32) -> egui::Response {
        let (field, field_response) =
            ui.allocate_exact_size(egui::vec2(field_width, FIELD_HEIGHT), egui::Sense::click());
        let background = ui.painter().add(egui::Shape::Noop);
        let text_rect = field.with_max_x(field.right() - SECRET_TRAILING_WIDTH);

        let secret = ui.put(
            text_rect,
            text_field(&mut self.input.user_secret, "Secret")
                .password(!self.show_secret)
                // A custom frame replaces `margin`, so the padding goes on the frame.
                .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(FIELD_PADDING, 0))),
        );
        if field_response.clicked() {
            secret.request_focus();
        }
        forget_undo_history(ui.ctx(), secret.id);

        // A square at the right end of the field; its highlight is inset evenly on all sides.
        let eye_rect = field.with_min_x(field.right() - field.height());
        let (eye_icon, eye_hint) = if self.show_secret {
            ("\u{f070}", "Hide secret")
        } else {
            ("\u{f06e}", "Show secret")
        };
        let eye = icon_button(
            ui,
            eye_rect,
            "secret_visibility",
            eye_icon,
            fonts::icon(ICON_SIZE),
            eye_hint,
            true,
        );
        if eye.clicked() {
            self.show_secret = !self.show_secret;
        }

        if !self.identicon.is_empty() {
            let galley = ui.painter().layout_no_wrap(
                self.identicon.clone(),
                egui::FontId::proportional(IDENTICON_SIZE),
                self.identicon_color,
            );
            // Same height and spacing as the eye's highlight, so the two line up.
            let chip_size = egui::vec2(
                (galley.size().x + 16.0).max(IDENTICON_CHIP_MIN_WIDTH),
                field.height() - 2.0 * HIGHLIGHT_INSET,
            );
            let chip = egui::Rect::from_min_size(
                egui::pos2(
                    eye_rect.left() - chip_size.x,
                    field.center().y - chip_size.y * 0.5,
                ),
                chip_size,
            );
            ui.painter().rect_filled(chip, HIGHLIGHT_RADIUS, CHIP_COLOR);
            ui.painter()
                .galley(chip.center() - galley.size() * 0.5, galley, Color32::WHITE);
            ui.interact(chip, ui.scope_id().with("identicon"), egui::Sense::hover())
                .on_hover_text(
                    "Identicon for this user and secret. If it looks unfamiliar, check for a typo.",
                );
        }

        let visuals = ui.visuals();
        let stroke = if secret.has_focus() {
            visuals.selection.stroke
        } else if ui.rect_contains_pointer(field) {
            visuals.widgets.hovered.bg_stroke
        } else {
            egui::Stroke::NONE
        };
        ui.painter().set(
            background,
            egui::Shape::rect_filled(field, CORNER_RADIUS, visuals.extreme_bg_color),
        );
        ui.painter()
            .rect_stroke(field, CORNER_RADIUS, stroke, egui::StrokeKind::Inside);

        secret
    }

    fn show_site_fields(&mut self, ui: &mut egui::Ui, field_width: f32) -> bool {
        let icon = row_icon(
            ui,
            "\u{f0ac}",
            "Site",
            "The site or service this password is for. Press Enter to copy the password.",
        );
        let site_name = ui
            .add_sized(
                [field_width, FIELD_HEIGHT],
                text_field(&mut self.input.site_name, "Site"),
            )
            .labelled_by(icon.id);
        self.copy_requested |= submitted(&site_name);
        if self.site_password.is_some() {
            self.show_enter_hint(ui, &site_name);
        }
        ui.end_row();

        let mut pw_type = self.input.pw_type;
        let mut counter = self.input.counter;
        row_icon(
            ui,
            "\u{f1de}",
            "Password settings",
            "Password type, and a counter to bump when a site needs a new password.",
        );
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = FIELD_GAP;
            let type_width = TYPE_WIDTH.min(field_width * 0.6);
            password_type_selector(ui, &mut pw_type, type_width);
            counter_stepper(ui, &mut counter, field_width - type_width - FIELD_GAP);
        });
        ui.end_row();

        let changed =
            site_name.changed() || pw_type != self.input.pw_type || counter != self.input.counter;
        self.input.pw_type = pw_type;
        self.input.counter = counter;
        changed
    }

    /// A muted "⏎ copy" at the right end of the site field, unless the site name reaches it.
    fn show_enter_hint(&self, ui: &egui::Ui, field: &egui::Response) {
        let painter = ui.painter();
        let glyph = painter.layout_no_wrap("\u{23ce}".into(), fonts::icon(ICON_SIZE), ICON_COLOR);
        let word = painter.layout_no_wrap(
            "copy".into(),
            egui::FontId::proportional(HINT_SIZE),
            MUTED_TEXT_COLOR,
        );
        let gap = 4.0;
        let hint_width = glyph.size().x + gap + word.size().x;
        let name_width = painter
            .layout_no_wrap(
                self.input.site_name.clone(),
                egui::FontId::proportional(TEXT_SIZE),
                TEXT_COLOR,
            )
            .size()
            .x;
        let padding = f32::from(FIELD_PADDING);
        if padding + name_width + 16.0 + hint_width + padding > field.rect.width() {
            return;
        }
        let right = field.rect.right() - padding;
        let center_y = field.rect.center().y;
        painter.galley(
            egui::pos2(right - word.size().x, center_y - word.size().y * 0.5),
            word,
            MUTED_TEXT_COLOR,
        );
        painter.galley(
            egui::pos2(right - hint_width, center_y - glyph.size().y * 0.5),
            glyph,
            ICON_COLOR,
        );
    }

    fn handle_input_changes(&mut self, credentials_changed: bool, site_changed: bool) {
        if credentials_changed || site_changed {
            // A copy queued for the old input would copy the wrong password.
            self.copy_pending = false;
            self.copied_at = None;
        }
        if credentials_changed {
            self.derivation_revision = self.derivation_revision.wrapping_add(1);
            // Keep showing the old password until the new key is ready, instead of flashing
            // a placeholder on every keystroke; `deriving_since` keeps it from being copied.
            self.user_key = None;
            self.deriving_since.get_or_insert_with(Instant::now);
            let secret = SecStr::from(self.input.user_secret.clone());
            self.update_identicon(&secret);
            let _ = self.derive_tx.send(DeriveRequest {
                revision: self.derivation_revision,
                user_name: self.input.user_name.clone(),
                user_secret: secret,
            });
        } else if site_changed
            && self.deriving_since.is_none()
            && let Err(error) = self.update_site_password()
        {
            // While deriving, the new key recomputes the password for the new site anyway.
            log::error!("Failed to generate site password: {error}");
            self.site_password = None;
        }
    }

    fn show_password(&mut self, ui: &mut egui::Ui) {
        ui.add_space(32.0);

        let password_text = self.password_text();
        // A stale password dims only if the new one is slow to come, so typing doesn't flicker.
        let stale = self.deriving_since.is_some_and(|since| {
            let elapsed = since.elapsed();
            if elapsed < STALE_DIM_DELAY {
                ui.ctx().request_repaint_after(STALE_DIM_DELAY - elapsed);
            }
            elapsed >= STALE_DIM_DELAY
        });
        let color = if self.site_password.is_some() && !stale {
            PASSWORD_COLOR
        } else {
            INACTIVE_PASSWORD_COLOR
        };
        // Shrink long passwords (Maximum is 20 characters) to fit the window width.
        let full_width = ui
            .painter()
            .layout_no_wrap(
                password_text.to_owned(),
                fonts::password(PASSWORD_SIZE),
                color,
            )
            .size()
            .x;
        let max_width = ui.available_width() - 2.0 * PASSWORD_MARGIN;
        let size = if full_width > max_width {
            (PASSWORD_SIZE * max_width / full_width).floor()
        } else {
            PASSWORD_SIZE
        };
        // A fixed-height row, so the button below stays put when the size changes.
        let row_height = ui.fonts_mut(|fonts| fonts.row_height(&fonts::password(PASSWORD_SIZE)));
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), row_height),
            egui::Layout::centered_and_justified(egui::Direction::TopDown),
            |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(password_text)
                            .font(fonts::password(size))
                            .color(color),
                    )
                    .selectable(true),
                );
            },
        );
        ui.add_space(16.0);
        self.show_copy_button(ui);
        ui.add_space(8.0);
        if let Some(hint) = self.clipboard_hint() {
            ui.label(RichText::new(hint).size(HINT_SIZE).color(MUTED_TEXT_COLOR));
        }
    }

    /// The countdown until the clipboard is wiped, while one is running.
    fn clipboard_hint(&self) -> Option<String> {
        let remaining = self.clipboard.remaining()?;
        // Round up, so the countdown reads 30 right after copying and 1 just before clearing.
        Some(format!(
            "Clipboard clears in {} s",
            remaining.as_millis().div_ceil(1000)
        ))
    }

    fn password_text(&self) -> &str {
        self.site_password.as_ref().map_or("...", SecUtf8::unsecure)
    }

    fn show_copy_button(&mut self, ui: &mut egui::Ui) {
        let has_password = self.site_password.is_some();
        let copied = self
            .copied_at
            .is_some_and(|at| at.elapsed() < COPIED_FEEDBACK);
        let (label, text_color, [fill, hover_fill, active_fill]) = if copied {
            (
                "Copied",
                COPIED_TEXT_COLOR,
                [COPIED_COLOR, COPIED_COLOR, COPIED_COLOR],
            )
        } else {
            (
                "Copy password",
                ACCENT_TEXT_COLOR,
                [ACCENT_COLOR, ACCENT_HOVER_COLOR, ACCENT_ACTIVE_COLOR],
            )
        };
        let copy_button = ui
            .scope(|ui| {
                // Hover brightens the accent fill rather than drawing the grey outline.
                let widgets = &mut ui.visuals_mut().widgets;
                for (state, fill) in [
                    (&mut widgets.inactive, fill),
                    (&mut widgets.hovered, hover_fill),
                    (&mut widgets.active, active_fill),
                ] {
                    state.weak_bg_fill = fill;
                    state.bg_fill = fill;
                    state.bg_stroke = egui::Stroke::NONE;
                }
                ui.add_enabled(
                    has_password,
                    egui::Button::new(RichText::new(label).size(TEXT_SIZE).color(text_color))
                        .min_size(egui::vec2(COPY_BUTTON_WIDTH, FIELD_HEIGHT)),
                )
            })
            .inner
            .on_hover_text("Enter in any field, or Ctrl+C, also copies the password.");
        focus_ring(ui, &copy_button, copy_button.rect, CORNER_RADIUS);
        if copy_button.clicked() || self.copy_requested {
            self.copy_password(ui.ctx());
        }
    }

    /// Copies the site password, if there is one, and starts the clipboard countdown.
    fn copy_password(&mut self, ctx: &egui::Context) {
        if self.deriving_since.is_some() {
            self.copy_pending = true;
            return;
        }
        let Some(password) = &self.site_password else {
            return;
        };
        self.clipboard
            .copy(ctx, password.unsecure(), CLIPBOARD_CLEAR_AFTER);
        self.copied_at = Some(Instant::now());
    }

    /// Ctrl+C (Cmd+C on macOS) with no text selected copies the whole password.
    fn copy_shortcut_pressed(&self, ctx: &egui::Context) -> bool {
        // egui-winit turns the shortcut into `Event::Copy`; other backends may send the raw key.
        let copy = ctx.input(|input| {
            input.events.contains(&egui::Event::Copy)
                || input.modifiers.command && input.key_pressed(egui::Key::C)
        });
        if !copy {
            return false;
        }
        let label_selected = ctx
            .plugin::<egui::text_selection::LabelSelectionState>()
            .lock()
            .has_selection();
        let field_selected = ctx.memory(|memory| memory.focused()).is_some_and(|id| {
            egui::TextEdit::load_state(ctx, id)
                .and_then(|state| state.cursor.char_range())
                .is_some_and(|range| !range.is_empty())
        });
        !label_selected && !field_selected
    }

    fn update_site_password(&mut self) -> Result<(), SpectreError> {
        self.site_password = match (&self.user_key, self.input.site_name.is_empty()) {
            (Some(user_key), false) => {
                let seed = spectre_rs_core::gen_site_seed(
                    &self.input.site_name,
                    user_key,
                    spectre_rs_core::Scope::Authentication,
                    self.input.counter,
                )?;
                Some(spectre_rs_core::gen_site_password(
                    &seed,
                    self.input.pw_type,
                )?)
            }
            _ => None,
        };
        Ok(())
    }

    fn update_identicon(&mut self, secret: &SecStr) {
        if self.input.user_name.is_empty() || secret.unsecure().is_empty() {
            self.identicon.clear();
            self.identicon_color = Color32::WHITE;
            return;
        }

        let identicon = Identicon::new(&self.input.user_name, secret);
        self.identicon_color = theme::identicon_color(identicon.color);
        self.identicon = identicon.to_string();
    }
}
