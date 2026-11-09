use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use egui::{Color32, RichText};
use secstr::{SecStr, SecUtf8};
use zeroize::Zeroize;

mod clipboard;

use clipboard::PasswordClipboard;

#[cfg(all(feature = "dev-inspection", not(debug_assertions)))]
compile_error!("the dev-inspection feature is only available in debug builds");

/// Fonts appended to the proportional family, in fallback order.
///
/// egui's default fonts (without the `monochrome_emoji_fonts` feature) cover none of the
/// identicon glyphs, so these must cover every one of them; see the test below.
/// The two `*-Identicon` files are subsets holding only the glyphs the others lack.
const FALLBACK_FONTS: &[(&str, &[u8])] = &[
    ("fontawesome", FIRA_MONO_MEDIUM),
    (
        "noto_symbols2",
        include_bytes!("../assets/fonts/NotoSansSymbols2-Regular.ttf"),
    ),
    (
        "noto_symbols_identicon",
        include_bytes!("../assets/fonts/NotoSansSymbols-Identicon.ttf"),
    ),
    (
        "noto_emoji_identicon",
        include_bytes!("../assets/fonts/NotoEmoji-Identicon.ttf"),
    ),
];

/// Nerd Font with proportional icon widths. The monospace variant squeezes icons into one cell
/// and lets them overflow it, which puts them visibly off-center.
const ICON_FONT: (&str, &[u8]) = (
    "icons",
    include_bytes!("../assets/fonts/FiraMonoNerdFontPropo-Medium.otf"),
);

fn icon_font(size: f32) -> egui::FontId {
    egui::FontId::new(size, egui::FontFamily::Name(ICON_FONT.0.into()))
}

/// Fira Mono Medium: a dotted zero and distinct `l`/`1`/`I`, so passwords read unambiguously.
/// Also the first proportional fallback, for the icon glyphs it carries.
const FIRA_MONO_MEDIUM: &[u8] = include_bytes!("../assets/fonts/FiraMonoNerdFont-Medium.otf");
const PASSWORD_FAMILY: &str = "password";

/// UI text font, subset to Latin; anything else falls back to egui's default fonts.
const TEXT_FONT: (&str, &[u8]) = (
    "fira_sans",
    include_bytes!("../assets/fonts/FiraSans-Regular-Latin.ttf"),
);

fn password_font(size: f32) -> egui::FontId {
    egui::FontId::new(size, egui::FontFamily::Name(PASSWORD_FAMILY.into()))
}

#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> eframe::Result {
    env_logger::init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("spectre-rs-gui")
            .with_icon(app_icon())
            // In points: eframe scales it by the zoom restored from storage. On the first
            // launch that is still 1.0, and `keep_window_size` corrects it on the first frame.
            .with_inner_size(WINDOW_SIZE)
            .with_resizable(false),
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        APP_TITLE,
        native_options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}

fn app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/spectre-rs-gui.png"))
        .expect("embedded application icon must be a valid PNG")
}

const APP_TITLE: &str = "Spectre Password Manager";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Window content size in egui points (before zoom).
const WINDOW_SIZE: egui::Vec2 = egui::vec2(436.0, 420.0);
const DEFAULT_ZOOM: f32 = 1.1;
const LABEL_WIDTH: f32 = 28.0;
const FIELD_GAP: f32 = 12.0;
const ROW_GAP: f32 = 12.0;
/// Horizontal text inset inside fields and buttons.
const FIELD_PADDING: i8 = 12;
const FIELD_WIDTH: f32 = 344.0;
const FIELD_HEIGHT: f32 = 44.0;
const TYPE_WIDTH: f32 = 204.0;
const CORNER_RADIUS: u8 = 9;
const ICON_SIZE: f32 = 16.0;
const TEXT_SIZE: f32 = 16.0;
const HINT_SIZE: f32 = 12.0;
const POPUP_ROW_HEIGHT: f32 = 28.0;
const PASSWORD_SIZE: f32 = 36.0;
const IDENTICON_SIZE: f32 = 17.0;
/// Room at the right of the secret field for the identicon chip and eye toggle.
const SECRET_TRAILING_WIDTH: f32 = 112.0;
const STEPPER_SEGMENT: f32 = 40.0;
/// Gap between a field's edge and the rounded hover highlight of a button inside it.
const HIGHLIGHT_INSET: f32 = 6.0;
const HIGHLIGHT_RADIUS: u8 = 6;
/// How long a stale password may show at full contrast while its replacement is derived.
const STALE_DIM_DELAY: Duration = Duration::from_millis(250);
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const USER_NAME_KEY: &str = "user_name";

const PANEL_COLOR: Color32 = Color32::from_rgb(0x1c, 0x1c, 0x1c);
const FIELD_COLOR: Color32 = Color32::from_rgb(0x0b, 0x0b, 0x0b);
const CONTROL_COLOR: Color32 = Color32::from_rgb(0x2f, 0x2f, 0x2f);
const CONTROL_HOVER_COLOR: Color32 = Color32::from_rgb(0x3a, 0x3a, 0x3a);
const CONTROL_ACTIVE_COLOR: Color32 = Color32::from_rgb(0x44, 0x44, 0x44);
const DIVIDER_COLOR: Color32 = Color32::from_rgb(0x44, 0x44, 0x44);
const CHIP_COLOR: Color32 = Color32::from_rgb(0x1e, 0x22, 0x24);
const ICON_COLOR: Color32 = Color32::from_rgb(0x8a, 0x8a, 0x8a);
const PLACEHOLDER_COLOR: Color32 = Color32::from_gray(0x8c);
const FOCUS_COLOR: Color32 = Color32::from_rgb(0x8c, 0xc4, 0xf2);
/// The type details on the selected (blue) dropdown row; about 5.7:1 there.
const SELECTED_DETAIL_COLOR: Color32 = Color32::from_rgb(0xcc, 0xe0, 0xee);
const MUTED_TEXT_COLOR: Color32 = Color32::from_rgb(0x9a, 0x9a, 0x9a);
const TEXT_COLOR: Color32 = Color32::from_rgb(0xe8, 0xe8, 0xe8);
const PASSWORD_COLOR: Color32 = Color32::from_rgb(0xf0, 0xf0, 0xf0);
const ACCENT_COLOR: Color32 = Color32::from_rgb(0x2b, 0x6c, 0xa3);
const ACCENT_HOVER_COLOR: Color32 = Color32::from_rgb(0x35, 0x7a, 0xb4);
const ACCENT_ACTIVE_COLOR: Color32 = Color32::from_rgb(0x24, 0x5d, 0x8d);
const ACCENT_TEXT_COLOR: Color32 = Color32::WHITE;

struct App {
    input: Input,
    derive_tx: mpsc::Sender<DeriveRequest>,
    derived_rx: mpsc::Receiver<DerivedKey>,
    derivation_revision: u64,
    user_key: Option<SecStr>,
    site_passwd: Option<SecUtf8>,
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
    user: String,
    user_secret: String,
    pwtype: spectre_rs_core::PwType,
    sitename: String,
    counter: u32,
}

struct DeriveRequest {
    revision: u64,
    user: String,
    user_secret: SecStr,
}

struct DerivedKey {
    revision: u64,
    user_key: Result<Option<SecStr>, spectre_rs_core::SpectreError>,
}

/// Room for the secret before the field has to reallocate, leaving an unwiped copy behind.
const SECRET_CAPACITY: usize = 256;

impl Input {
    fn new() -> Self {
        Self {
            user: String::new(),
            user_secret: String::with_capacity(SECRET_CAPACITY),
            sitename: String::new(),
            pwtype: spectre_rs_core::PwType::Medium,
            counter: 1,
        }
    }
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("user", &self.user)
            .field("user_secret", &"***SECRET***")
            .field("pwtype", &self.pwtype)
            .field("sitename", &self.sitename)
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
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let saved_user = cc
            .storage
            .and_then(|storage| eframe::get_value::<String>(storage, USER_NAME_KEY));
        // Nothing saved yet means this is the first launch. Later launches keep the zoom the
        // user chose, which egui restores on its own.
        if saved_user.is_none() {
            cc.egui_ctx.set_zoom_factor(DEFAULT_ZOOM);
        }

        #[cfg(feature = "dev-inspection")]
        attach_inspection(&cc.egui_ctx);

        apply_theme(&cc.egui_ctx);

        for (name, data, family) in [
            (
                ICON_FONT.0,
                ICON_FONT.1,
                egui::FontFamily::Name(ICON_FONT.0.into()),
            ),
            (TEXT_FONT.0, TEXT_FONT.1, egui::FontFamily::Proportional),
            (
                PASSWORD_FAMILY,
                FIRA_MONO_MEDIUM,
                egui::FontFamily::Name(PASSWORD_FAMILY.into()),
            ),
        ] {
            cc.egui_ctx.add_font(egui::epaint::text::FontInsert::new(
                name,
                egui::FontData::from_static(data),
                vec![egui::epaint::text::InsertFontFamily {
                    family,
                    priority: egui::epaint::text::FontPriority::Highest,
                }],
            ));
        }
        for &(name, data) in FALLBACK_FONTS {
            cc.egui_ctx.add_font(egui::epaint::text::FontInsert::new(
                name,
                egui::FontData::from_static(data),
                vec![egui::epaint::text::InsertFontFamily {
                    family: egui::FontFamily::Proportional,
                    priority: egui::epaint::text::FontPriority::Lowest,
                }],
            ));
        }

        let mut input = Input::new();
        input.user = saved_user.unwrap_or_default();
        let (derive_tx, derived_rx) = start_key_derivation(cc.egui_ctx.clone());

        Self {
            input,
            derive_tx,
            derived_rx,
            derivation_revision: 0,
            user_key: None,
            site_passwd: None,
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

/// Dark theme from the v0.2.4 layout: borderless fields on a dark panel, flat rounded controls.
fn apply_theme(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        let visuals = &mut style.visuals;
        visuals.panel_fill = PANEL_COLOR;
        visuals.window_fill = PANEL_COLOR;
        visuals.extreme_bg_color = FIELD_COLOR;
        visuals.window_corner_radius = CORNER_RADIUS.into();
        visuals.menu_corner_radius = CORNER_RADIUS.into();
        // Placeholders double as field labels, so they need full text contrast (about 5.8:1).
        visuals.weak_text_color = Some(PLACEHOLDER_COLOR);
        visuals.selection.stroke.color = FOCUS_COLOR;

        let widgets = &mut visuals.widgets;
        for (state, fill) in [
            (&mut widgets.inactive, CONTROL_COLOR),
            (&mut widgets.hovered, CONTROL_HOVER_COLOR),
            (&mut widgets.active, CONTROL_ACTIVE_COLOR),
            (&mut widgets.open, CONTROL_HOVER_COLOR),
        ] {
            state.bg_fill = fill;
            state.weak_bg_fill = fill;
            state.corner_radius = CORNER_RADIUS.into();
            state.expansion = 0.0;
        }
        widgets.inactive.bg_stroke = egui::Stroke::NONE;
        widgets.inactive.fg_stroke.color = TEXT_COLOR;
        widgets.hovered.bg_stroke = egui::Stroke::new(1.0, DIVIDER_COLOR);
        widgets.active.bg_stroke = egui::Stroke::NONE;
        widgets.open.bg_stroke = egui::Stroke::NONE;

        style.spacing.interact_size.y = FIELD_HEIGHT;
        style.spacing.button_padding = egui::vec2(FIELD_PADDING.into(), 4.0);
    });
}

fn start_key_derivation(
    ctx: egui::Context,
) -> (mpsc::Sender<DeriveRequest>, mpsc::Receiver<DerivedKey>) {
    let (derive_tx, derive_rx) = mpsc::channel::<DeriveRequest>();
    let (derived_tx, derived_rx) = mpsc::channel::<DerivedKey>();

    std::thread::spawn(move || {
        while let Ok(request) = derive_rx.recv() {
            // Skip queued intermediate password edits and derive only the latest input.
            let mut latest = request;
            while let Ok(newer) = derive_rx.try_recv() {
                latest = newer;
            }

            let user_key = derive_user_key(&latest);
            let _ = derived_tx.send(DerivedKey {
                revision: latest.revision,
                user_key,
            });
            ctx.request_repaint();
        }
    });

    (derive_tx, derived_rx)
}

fn derive_user_key(
    request: &DeriveRequest,
) -> Result<Option<SecStr>, spectre_rs_core::SpectreError> {
    if request.user.is_empty() || request.user_secret.unsecure().is_empty() {
        Ok(None)
    } else {
        spectre_rs_core::gen_user_key(
            &request.user,
            &request.user_secret,
            spectre_rs_core::Scope::Authentication,
        )
        .map(Some)
    }
}

#[cfg(feature = "dev-inspection")]
fn attach_inspection(ctx: &egui::Context) {
    let enabled = std::env::var("SPECTRE_UI_INSPECTION")
        .ok()
        .is_some_and(|value| {
            let value = value.trim();
            !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
        });

    if enabled {
        ctx.add_plugin(egui_inspection::InspectionPlugin::new(Some(
            APP_TITLE.to_owned(),
        )));
        match egui_inspection::serve(ctx, "127.0.0.1:5719") {
            Ok(()) => log::info!("egui inspection listening on 127.0.0.1:5719"),
            Err(error) => log::warn!("failed to start egui inspection: {error}"),
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
                        .color(Color32::from_gray(105)),
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
        eframe::set_value(storage, USER_NAME_KEY, &self.input.user);
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
                        self.site_passwd = None;
                    }
                }
                Err(error) => {
                    log::error!("Failed to derive user key: {error}");
                    self.user_key = None;
                    self.site_passwd = None;
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
        let username = ui
            .add_sized(
                [field_width, FIELD_HEIGHT],
                text_field(&mut self.input.user, "User"),
            )
            .labelled_by(icon.id);
        self.copy_requested |= submitted(&username);
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

        username.changed() || secret.changed()
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
            icon_font(ICON_SIZE),
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
                muted(self.identicon_color),
            );
            // Same height and spacing as the eye's highlight, so the two line up.
            let chip_size = egui::vec2(
                (galley.size().x + 16.0).max(47.0),
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
        let sitename = ui
            .add_sized(
                [field_width, FIELD_HEIGHT],
                text_field(&mut self.input.sitename, "Site"),
            )
            .labelled_by(icon.id);
        self.copy_requested |= submitted(&sitename);
        if self.site_passwd.is_some() {
            self.show_enter_hint(ui, &sitename);
        }
        ui.end_row();

        let mut pwtype = self.input.pwtype;
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
            password_type_selector(ui, &mut pwtype, type_width);
            counter_stepper(ui, &mut counter, field_width - type_width - FIELD_GAP);
        });
        ui.end_row();

        let changed =
            sitename.changed() || pwtype != self.input.pwtype || counter != self.input.counter;
        self.input.pwtype = pwtype;
        self.input.counter = counter;
        changed
    }

    /// A muted "⏎ copy" at the right end of the site field, unless the site name reaches it.
    fn show_enter_hint(&self, ui: &egui::Ui, field: &egui::Response) {
        let painter = ui.painter();
        let glyph = painter.layout_no_wrap("\u{23ce}".into(), icon_font(ICON_SIZE), ICON_COLOR);
        let word = painter.layout_no_wrap(
            "copy".into(),
            egui::FontId::proportional(HINT_SIZE),
            MUTED_TEXT_COLOR,
        );
        let gap = 4.0;
        let hint_width = glyph.size().x + gap + word.size().x;
        let name_width = painter
            .layout_no_wrap(
                self.input.sitename.clone(),
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
                user: self.input.user.clone(),
                user_secret: secret,
            });
        } else if site_changed
            && self.deriving_since.is_none()
            && let Err(error) = self.update_site_password()
        {
            // While deriving, the new key recomputes the password for the new site anyway.
            log::error!("Failed to generate site password: {error}");
            self.site_passwd = None;
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
        let color = if self.site_passwd.is_some() && !stale {
            PASSWORD_COLOR
        } else {
            Color32::from_gray(110)
        };
        // Shrink long passwords (Maximum is 20 characters) to fit the window width.
        let full_width = ui
            .painter()
            .layout_no_wrap(
                password_text.to_owned(),
                password_font(PASSWORD_SIZE),
                color,
            )
            .size()
            .x;
        let max_width = ui.available_width() - 40.0;
        let size = if full_width > max_width {
            (PASSWORD_SIZE * max_width / full_width).floor()
        } else {
            PASSWORD_SIZE
        };
        // A fixed-height row, so the button below stays put when the size changes.
        let row_height = ui.fonts_mut(|fonts| fonts.row_height(&password_font(PASSWORD_SIZE)));
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), row_height),
            egui::Layout::centered_and_justified(egui::Direction::TopDown),
            |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(password_text)
                            .font(password_font(size))
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
        self.site_passwd.as_ref().map_or("...", SecUtf8::unsecure)
    }

    fn show_copy_button(&mut self, ui: &mut egui::Ui) {
        let has_password = self.site_passwd.is_some();
        let copied = self
            .copied_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(2));
        let (label, text_color, [fill, hover_fill, active_fill]) = if copied {
            let fill = Color32::from_rgb(37, 61, 47);
            (
                "Copied",
                Color32::from_rgb(166, 220, 185),
                [fill, fill, fill],
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
                        .min_size(egui::vec2(184.0, FIELD_HEIGHT)),
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
        let Some(password) = &self.site_passwd else {
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

    fn update_site_password(&mut self) -> Result<(), spectre_rs_core::SpectreError> {
        self.site_passwd = match (&self.user_key, self.input.sitename.is_empty()) {
            (Some(user_key), false) => {
                let seed = spectre_rs_core::gen_site_seed(
                    &self.input.sitename,
                    user_key,
                    spectre_rs_core::Scope::Authentication,
                    self.input.counter,
                )?;
                Some(spectre_rs_core::gen_site_password(
                    &seed,
                    self.input.pwtype,
                )?)
            }
            _ => None,
        };
        Ok(())
    }

    fn update_identicon(&mut self, secret: &SecStr) {
        if self.input.user.is_empty() || secret.unsecure().is_empty() {
            self.identicon.clear();
            self.identicon_color = Color32::WHITE;
            return;
        }

        let icon = spectre_rs_core::identicon::Identicon::new(&self.input.user, secret);
        self.identicon_color = relaxed_identicon_color(icon.color);
        self.identicon = icon.to_string();
    }
}

/// The icon in front of a form row. Screen readers announce it as `name`, the row's label; the
/// longer `hint` is its tooltip, so it never covers the field below the one being hovered.
fn row_icon(ui: &mut egui::Ui, icon: &str, name: &str, hint: &str) -> egui::Response {
    let response = ui
        .label(
            RichText::new(icon)
                .font(icon_font(ICON_SIZE))
                .color(ICON_COLOR),
        )
        .on_hover_text(hint);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, name));
    response
}

/// Drops the undo history egui keeps for a text field, so it holds no old copies of the text.
///
/// Called every frame, because egui adds a snapshot whenever the text has settled for a moment.
fn forget_undo_history(ctx: &egui::Context, id: egui::Id) {
    if let Some(mut state) = egui::TextEdit::load_state(ctx, id) {
        state.clear_undoer();
        state.store(ctx, id);
    }
}

/// Whether Enter was pressed to leave this single-line field.
fn submitted(response: &egui::Response) -> bool {
    response.lost_focus()
        && response
            .ctx
            .input(|input| input.key_pressed(egui::Key::Enter))
}

fn text_field<'t>(text: &'t mut String, hint: &str) -> egui::TextEdit<'t> {
    egui::TextEdit::singleline(text)
        .font(egui::FontId::proportional(TEXT_SIZE))
        .text_color(TEXT_COLOR)
        .margin(egui::Margin::symmetric(FIELD_PADDING, 0))
        .align(egui::Align2::LEFT_CENTER)
        .hint_text(hint)
}

/// Blends an identicon color toward gray so it sits quietly inside the secret field.
fn muted(color: Color32) -> Color32 {
    color.lerp_to_gamma(Color32::from_gray(150), 0.35)
}

fn password_type_selector(ui: &mut egui::Ui, pwtype: &mut spectre_rs_core::PwType, width: f32) {
    let response = egui::ComboBox::from_id_salt("password_type")
        .selected_text(RichText::new(format!("{pwtype:?}")).size(TEXT_SIZE))
        .width(width)
        .show_ui(ui, |ui| {
            use spectre_rs_core::PwType;
            // Compact rows, so all six types fit below the field without scrolling.
            ui.spacing_mut().interact_size.y = POPUP_ROW_HEIGHT;
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                for (value, name, detail) in [
                    (PwType::Maximum, "Maximum", "20 · symbols"),
                    (PwType::Long, "Long", "14 · symbols"),
                    (PwType::Medium, "Medium", "8 · symbols"),
                    (PwType::Basic, "Basic", "8 · no symbols"),
                    (PwType::Short, "Short", "4 · no symbols"),
                    (PwType::Pin, "Pin", "4 · digits"),
                ] {
                    let selected = *pwtype == value;
                    let response =
                        ui.selectable_value(pwtype, value, RichText::new(name).size(TEXT_SIZE));
                    response.widget_info(|| {
                        egui::WidgetInfo::selected(
                            egui::Role::Button,
                            true,
                            selected,
                            format!("{name}, {detail}"),
                        )
                    });
                    // The length, right-aligned in muted text, so types compare at a glance.
                    let padding = ui.spacing().button_padding.x;
                    ui.painter().text(
                        egui::pos2(response.rect.right() - padding, response.rect.center().y),
                        egui::Align2::RIGHT_CENTER,
                        detail,
                        egui::FontId::proportional(HINT_SIZE + 1.0),
                        if selected {
                            SELECTED_DETAIL_COLOR
                        } else {
                            MUTED_TEXT_COLOR
                        },
                    );
                }
            });
        })
        .response
        .on_hover_text("Password type");
    focus_ring(ui, &response, response.rect, CORNER_RADIUS);
}

/// A flat button that reacts across all of `rect`, with a rounded highlight inset inside it.
///
/// Drawn by hand because the theme's minimum widget height (the field height) would otherwise
/// make a smaller `Button` overflow `rect` and shift its hover frame off-center.
fn icon_button(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    id_salt: &str,
    glyph: &str,
    font: egui::FontId,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let response = ui
        .interact(rect, ui.scope_id().with(id_salt), sense)
        .on_hover_text(label);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, label));

    let highlight = highlight_rect(rect);
    if enabled && (response.hovered() || response.has_focus()) {
        let fill = if response.is_pointer_button_down_on() {
            CONTROL_ACTIVE_COLOR
        } else {
            CONTROL_HOVER_COLOR
        };
        ui.painter().rect_filled(highlight, HIGHLIGHT_RADIUS, fill);
    }
    focus_ring(ui, &response, highlight, HIGHLIGHT_RADIUS);
    let color = if !enabled {
        Color32::from_gray(90)
    } else if response.hovered() {
        TEXT_COLOR
    } else {
        MUTED_TEXT_COLOR
    };
    ui.painter().text(
        highlight.center(),
        egui::Align2::CENTER_CENTER,
        glyph,
        font,
        color,
    );
    response
}

/// A visible keyboard-focus indicator (WCAG 2.4.7) for widgets that have no outline of their own.
fn focus_ring(ui: &egui::Ui, response: &egui::Response, rect: egui::Rect, radius: u8) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect,
            radius,
            egui::Stroke::new(2.0, FOCUS_COLOR),
            egui::StrokeKind::Inside,
        );
    }
}

/// The hover highlight inside a control segment: inset evenly, but never narrower than tall.
fn highlight_rect(rect: egui::Rect) -> egui::Rect {
    let height = rect.height() - 2.0 * HIGHLIGHT_INSET;
    let width = (rect.width() - 2.0 * HIGHLIGHT_INSET).max(height.min(rect.width() - 8.0));
    egui::Rect::from_center_size(rect.center(), egui::vec2(width, height))
}

/// A `[−] n [+]` stepper for the password counter; the number can also be dragged or typed.
fn counter_stepper(ui: &mut egui::Ui, counter: &mut u32, width: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, FIELD_HEIGHT), egui::Sense::hover());
    ui.painter().rect_filled(rect, CORNER_RADIUS, CONTROL_COLOR);

    let minus_rect = rect.with_max_x(rect.left() + STEPPER_SEGMENT);
    let plus_rect = rect.with_min_x(rect.right() - STEPPER_SEGMENT);
    let value_rect = rect
        .with_min_x(minus_rect.right())
        .with_max_x(plus_rect.left());

    let minus = icon_button(
        ui,
        minus_rect,
        "counter_minus",
        "\u{2212}",
        egui::FontId::proportional(TEXT_SIZE),
        "Previous counter",
        *counter > 1,
    );
    if minus.clicked() {
        *counter = counter.saturating_sub(1).max(1);
    }
    let plus = icon_button(
        ui,
        plus_rect,
        "counter_plus",
        "+",
        egui::FontId::proportional(TEXT_SIZE),
        "Next counter",
        *counter < u32::MAX,
    );
    if plus.clicked() {
        *counter = counter.saturating_add(1);
    }

    ui.scope(|ui| {
        let counter_style = egui::TextStyle::Name("counter".into());
        let style = ui.style_mut();
        style
            .text_styles
            .insert(counter_style.clone(), egui::FontId::proportional(TEXT_SIZE));
        style.drag_value_text_style = counter_style;
        // Highlight the number like the buttons beside it: an inset pill, no outline.
        let value_highlight = value_rect.shrink2(egui::vec2(4.0, HIGHLIGHT_INSET));
        style.spacing.interact_size.y = value_highlight.height();
        let widgets = &mut style.visuals.widgets;
        widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
        widgets.inactive.bg_fill = Color32::TRANSPARENT;
        for state in [
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
        ] {
            state.corner_radius = HIGHLIGHT_RADIUS.into();
            state.bg_stroke = egui::Stroke::NONE;
            state.expansion = 0.0;
        }
        let value = ui
            .put(
                value_highlight,
                egui::DragValue::new(counter).range(1..=u32::MAX).speed(0.1),
            )
            .on_hover_text("Counter. Drag or type to change it.");
        focus_ring(ui, &value, value_highlight, HIGHLIGHT_RADIUS);
    });

    // Dividers go on top so the hover fills of the segments don't cover them.
    let divider_y = egui::Rangef::new(rect.top() + 8.0, rect.bottom() - 8.0);
    let divider = egui::Stroke::new(1.0, DIVIDER_COLOR);
    ui.painter().vline(minus_rect.right(), divider_y, divider);
    ui.painter().vline(plus_rect.left(), divider_y, divider);
}

/// The identicon colors from the One Dark palette, softer than the terminal's primaries.
fn relaxed_identicon_color(color: spectre_rs_core::identicon::IdenticonColor) -> Color32 {
    use spectre_rs_core::identicon::IdenticonColor;
    match color {
        IdenticonColor::Red => Color32::from_rgb(0xe0, 0x6c, 0x75),
        IdenticonColor::Green => Color32::from_rgb(0x98, 0xc3, 0x79),
        IdenticonColor::Yellow => Color32::from_rgb(0xe5, 0xc0, 0x7b),
        IdenticonColor::Blue => Color32::from_rgb(0x61, 0xaf, 0xef),
        IdenticonColor::Magenta => Color32::from_rgb(0xc6, 0x78, 0xdd),
        IdenticonColor::Cyan => Color32::from_rgb(0x56, 0xb6, 0xc2),
        IdenticonColor::White => Color32::from_rgb(0xab, 0xb2, 0xbf),
    }
}

#[cfg(test)]
mod tests {
    use skrifa::{FontRef, MetadataProvider};
    use spectre_rs_core::identicon::{
        IDENTICON_ACCESSORIES, IDENTICON_BODIES, IDENTICON_LEFT_ARMS, IDENTICON_RIGHT_ARMS,
    };

    #[test]
    fn bundled_fonts_cover_every_identicon_glyph() {
        let fonts: Vec<FontRef> = super::FALLBACK_FONTS
            .iter()
            .map(|(name, data)| {
                FontRef::new(data).unwrap_or_else(|e| panic!("cannot parse font {name}: {e}"))
            })
            .collect();

        let missing: Vec<char> = [
            IDENTICON_LEFT_ARMS,
            IDENTICON_RIGHT_ARMS,
            IDENTICON_BODIES,
            IDENTICON_ACCESSORIES,
        ]
        .concat()
        .iter()
        .flat_map(|glyph| glyph.chars())
        .filter(|&c| fonts.iter().all(|font| font.charmap().map(c).is_none()))
        .collect();

        assert!(missing.is_empty(), "no bundled font has: {missing:?}");
    }
}
