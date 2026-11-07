use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use egui::{Color32, RichText};
use secstr::SecStr;

#[cfg(all(feature = "dev-inspection", not(debug_assertions)))]
compile_error!("the dev-inspection feature is only available in debug builds");

#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> eframe::Result {
    env_logger::init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([440.0, 440.0])
            .with_min_inner_size([440.0, 440.0]),
        ..Default::default()
    };
    eframe::run_native(
        APP_TITLE,
        native_options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}

const APP_TITLE: &str = "Spectre Password Manager";

#[derive(Debug)]
struct App {
    input: Input,
    derive_tx: mpsc::Sender<DeriveRequest>,
    derived_rx: mpsc::Receiver<DerivedKey>,
    derivation_revision: u64,
    user_key: Option<SecStr>,
    site_passwd: Option<SecStr>,
    identicon: RichText,
    identicon_color: Color32,
    copied_at: Option<Instant>,
}

#[derive(Debug)]
struct Input {
    user: String,
    user_secret: String,
    pwtype: spectre_rs::PwType,
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
    user_key: Result<Option<SecStr>, spectre_rs::SpectreError>,
}

impl Input {
    fn new() -> Self {
        Self {
            user: String::new(),
            user_secret: String::new(),
            sitename: String::new(),
            pwtype: spectre_rs::PwType::Medium,
            counter: 1,
        }
    }
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_zoom_factor(1.1);

        #[cfg(feature = "dev-inspection")]
        attach_inspection(&cc.egui_ctx);

        cc.egui_ctx.add_font(egui::epaint::text::FontInsert::new(
            "fontawesome",
            egui::FontData::from_static(include_bytes!(
                "../assets/fonts/FiraMonoNerdFont-Medium.otf"
            )),
            vec![egui::epaint::text::InsertFontFamily {
                family: egui::FontFamily::Proportional,
                priority: egui::epaint::text::FontPriority::Lowest,
            }],
        ));

        let input = Input::new();
        let (derive_tx, derive_rx) = mpsc::channel::<DeriveRequest>();
        let (derived_tx, derived_rx) = mpsc::channel::<DerivedKey>();
        let egui_ctx = cc.egui_ctx.clone();

        std::thread::spawn({
            let egui_ctx = egui_ctx.clone();
            move || {
                while let Ok(request) = derive_rx.recv() {
                    // Skip queued intermediate password edits and derive only the latest input.
                    let mut latest = request;
                    while let Ok(newer) = derive_rx.try_recv() {
                        latest = newer;
                    }

                    let user_key =
                        if latest.user.is_empty() || latest.user_secret.unsecure().is_empty() {
                            Ok(None)
                        } else {
                            spectre_rs::gen_user_key(
                                &latest.user,
                                &latest.user_secret,
                                spectre_rs::Scope::Authentication,
                            )
                            .map(Some)
                        };
                    let _ = derived_tx.send(DerivedKey {
                        revision: latest.revision,
                        user_key,
                    });
                    egui_ctx.request_repaint();
                }
            }
        });

        Self {
            input,
            derive_tx,
            derived_rx,
            derivation_revision: 0,
            user_key: None,
            site_passwd: None,
            identicon: RichText::new(""),
            identicon_color: Color32::WHITE,
            copied_at: None,
        }
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
        while let Ok(derived) = self.derived_rx.try_recv() {
            if derived.revision == self.derivation_revision {
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
            }
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                const LABEL_WIDTH: f32 = 30.0;
                const FIELD_GAP: f32 = 8.0;
                const FIELD_HEIGHT: f32 = 38.0;
                const LABEL_SIZE: f32 = 16.0;
                let field_width =
                    (ui.available_width() - LABEL_WIDTH - FIELD_GAP).clamp(220.0, 300.0);
                let form_width = LABEL_WIDTH + FIELD_GAP + field_width;
                let counter_width = (field_width * 0.29).clamp(72.0, 88.0);
                let type_width = field_width - counter_width - FIELD_GAP;

                ui.spacing_mut().interact_size.y = FIELD_HEIGHT;
                ui.add_space(20.0);

                let (username, secret, sitename, pwtype, counter) = ui
                    .horizontal(|ui| {
                        ui.add_space(((ui.available_width() - form_width) * 0.5).max(0.0));
                        ui.vertical(|ui| {
                            let (username, secret) = egui::Grid::new("credential_fields")
                                .num_columns(2)
                                .min_col_width(LABEL_WIDTH)
                                .spacing([FIELD_GAP, 10.0])
                                .show(ui, |ui| {
                                    ui.label(RichText::new("\u{f007}").size(LABEL_SIZE))
                                        .on_hover_text("User");
                                    let username = ui.add_sized(
                                        [field_width, FIELD_HEIGHT],
                                        egui::TextEdit::singleline(&mut self.input.user)
                                            .font(egui::FontId::proportional(LABEL_SIZE))
                                            .align(egui::Align2::LEFT_CENTER)
                                            .hint_text("User"),
                                    )
                                    .on_hover_text(
                                        "Name used to derive your passwords. Keep it consistent across devices.",
                                    );
                                    ui.end_row();

                                    ui.label(RichText::new("\u{f084}").size(LABEL_SIZE))
                                        .on_hover_text("Secret");
                                    let secret = ui.add_sized(
                                        [field_width, FIELD_HEIGHT],
                                        egui::TextEdit::singleline(&mut self.input.user_secret)
                                            .font(egui::FontId::proportional(LABEL_SIZE))
                                            .align(egui::Align2::LEFT_CENTER)
                                            .password(true)
                                            .hint_text("Secret"),
                                    )
                                    .on_hover_text(
                                        "Your master secret, used locally to derive your account key.",
                                    );
                                    ui.end_row();
                                    (username, secret)
                                })
                                .inner;

                            ui.add_space(12.0);

                            let (sitename, pwtype, counter) = egui::Grid::new("site_fields")
                                .num_columns(2)
                                .min_col_width(LABEL_WIDTH)
                                .spacing([FIELD_GAP, 10.0])
                                .show(ui, |ui| {
                                    ui.label(RichText::new("\u{f0ac}").size(LABEL_SIZE))
                                        .on_hover_text("Site");
                                    let sitename = ui.add_sized(
                                        [field_width, FIELD_HEIGHT],
                                        egui::TextEdit::singleline(&mut self.input.sitename)
                                            .font(egui::FontId::proportional(LABEL_SIZE))
                                            .align(egui::Align2::LEFT_CENTER)
                                            .hint_text("Site"),
                                    )
                                    .on_hover_text("The site or service this password is for.");
                                    ui.end_row();

                                    let mut pwtype = self.input.pwtype;
                                    let mut counter = self.input.counter;
                                    ui.label(RichText::new("\u{f1de}").size(LABEL_SIZE))
                                        .on_hover_text("Password type");
                                    ui.horizontal(|ui| {
                                        egui::ComboBox::from_id_salt("password_type")
                                            .selected_text(
                                                RichText::new(format!("{pwtype:?}"))
                                                    .size(LABEL_SIZE),
                                            )
                                            .width(type_width)
                                            .show_ui(ui, |ui| {
                                                ui.selectable_value(
                                                    &mut pwtype,
                                                    spectre_rs::PwType::Medium,
                                                    RichText::new("Medium").size(LABEL_SIZE),
                                                )
                                                .on_hover_text("8 characters with symbols.");
                                                ui.selectable_value(
                                                    &mut pwtype,
                                                    spectre_rs::PwType::Long,
                                                    RichText::new("Long").size(LABEL_SIZE),
                                                )
                                                .on_hover_text("14 characters with symbols.");
                                                ui.selectable_value(
                                                    &mut pwtype,
                                                    spectre_rs::PwType::Basic,
                                                    RichText::new("Basic").size(LABEL_SIZE),
                                                )
                                                .on_hover_text("8 characters without symbols.");
                                                ui.selectable_value(
                                                    &mut pwtype,
                                                    spectre_rs::PwType::Pin,
                                                    RichText::new("Pin").size(LABEL_SIZE),
                                                )
                                                .on_hover_text("4 numeric digits.");
                                            });
                                        ui.add_sized(
                                            [counter_width, FIELD_HEIGHT],
                                            egui::DragValue::new(&mut counter)
                                                .range(1..=u32::MAX)
                                                .speed(0.1),
                                        )
                                        .on_hover_text(
                                            "Password counter. Increase it to create a new password for this site.",
                                        );
                                    });
                                    ui.end_row();
                                    (sitename, pwtype, counter)
                                })
                                .inner;
                            (username, secret, sitename, pwtype, counter)
                        })
                        .inner
                    })
                    .inner;

                let credentials_changed = secret.changed() || username.changed();
                let site_changed = sitename.changed()
                    || pwtype != self.input.pwtype
                    || counter != self.input.counter;
                if pwtype != self.input.pwtype {
                    self.input.pwtype = pwtype;
                }
                self.input.counter = counter;
                if credentials_changed {
                    self.copied_at = None;
                    self.derivation_revision = self.derivation_revision.wrapping_add(1);
                    self.user_key = None;
                    self.site_passwd = None;
                    let secret = SecStr::from(self.input.user_secret.clone());
                    self.update_identicon(&secret);
                    let _ = self.derive_tx.send(DeriveRequest {
                        revision: self.derivation_revision,
                        user: self.input.user.clone(),
                        user_secret: secret,
                    });
                } else if site_changed && let Err(error) = self.update_site_password() {
                    log::error!("Failed to generate site password: {error}");
                    self.site_passwd = None;
                }
                if site_changed {
                    self.copied_at = None;
                }

                ui.add_space(24.0);
                let has_password = self.site_passwd.is_some();
                let has_credentials =
                    !self.input.user.is_empty() && !self.input.user_secret.is_empty();
                if has_credentials {
                    ui.add(egui::Label::new(self.identicon.clone()));
                } else {
                    ui.add(egui::Label::new(
                        RichText::new("?").size(26.0).color(Color32::from_gray(160)),
                    ));
                }

                ui.add_space(12.0);
                let password_text = self
                    .site_passwd
                    .as_ref()
                    .map(|password| std::str::from_utf8(password.unsecure()).unwrap().to_owned())
                    .unwrap_or_else(|| "...".to_owned());
                let password_rich_text = RichText::new(&password_text)
                    .monospace()
                    .size(28.0)
                    .strong();
                let password_rich_text = if has_password {
                    password_rich_text
                } else {
                    password_rich_text.color(Color32::from_gray(160))
                };
                ui.add(egui::Label::new(password_rich_text).selectable(true));

                ui.add_space(12.0);
                let copied = self
                    .copied_at
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(2));
                let copy_button = ui
                    .add_enabled_ui(has_password, |ui| {
                        let button = if copied {
                            egui::Button::new(
                                RichText::new("Copied")
                                    .size(LABEL_SIZE)
                                    .color(Color32::from_rgb(166, 220, 185)),
                            )
                            .fill(Color32::from_rgb(37, 61, 47))
                        } else {
                            egui::Button::new(
                                RichText::new("Copy password").size(LABEL_SIZE),
                            )
                        };
                        ui.add(button)
                    })
                    .inner;
                if copy_button.clicked() {
                    ui.ctx().copy_text(password_text);
                    self.copied_at = Some(Instant::now());
                    ui.ctx().request_repaint_after(Duration::from_secs(2));
                }
            });
        });
    }
}

impl App {
    fn update_site_password(&mut self) -> Result<(), spectre_rs::SpectreError> {
        self.site_passwd = match (&self.user_key, self.input.sitename.is_empty()) {
            (Some(user_key), false) => {
                let seed = spectre_rs::gen_site_seed(
                    &self.input.sitename,
                    user_key,
                    spectre_rs::Scope::Authentication,
                    self.input.counter,
                )?;
                Some(spectre_rs::gen_site_password(&seed, self.input.pwtype)?)
            }
            _ => None,
        };
        Ok(())
    }

    fn update_identicon(&mut self, secret: &SecStr) {
        if self.input.user.is_empty() || secret.unsecure().is_empty() {
            self.identicon = RichText::new("");
            self.identicon_color = Color32::WHITE;
            return;
        }

        let icon = spectre_rs::identicon::Identicon::from(secret, &self.input.user);
        self.identicon_color = relaxed_identicon_color(icon.get_ansi_color());
        self.identicon = RichText::new(std::format!(
            "{}{}{}{}",
            icon.left_arm,
            icon.body,
            icon.right_arm,
            icon.accessory
        ))
        .size(26.0)
        .color(self.identicon_color);
    }
}

fn relaxed_identicon_color(color: colored::Color) -> Color32 {
    use colored::Color::*;
    match color {
        Black => Color32::from_rgb(0x28, 0x2c, 0x34),
        Red => Color32::from_rgb(0xe0, 0x6c, 0x75),
        Green => Color32::from_rgb(0x98, 0xc3, 0x79),
        Yellow => Color32::from_rgb(0xe5, 0xc0, 0x7b),
        Blue => Color32::from_rgb(0x61, 0xaf, 0xef),
        Magenta => Color32::from_rgb(0xc6, 0x78, 0xdd),
        Cyan => Color32::from_rgb(0x56, 0xb6, 0xc2),
        White => Color32::from_rgb(0xab, 0xb2, 0xbf),
        BrightBlack => Color32::from_rgb(0x5c, 0x63, 0x70),
        BrightRed => Color32::from_rgb(0xe0, 0x6c, 0x75),
        BrightGreen => Color32::from_rgb(0x98, 0xc3, 0x79),
        BrightYellow => Color32::from_rgb(0xe5, 0xc0, 0x7b),
        BrightBlue => Color32::from_rgb(0x61, 0xaf, 0xef),
        BrightMagenta => Color32::from_rgb(0xc6, 0x78, 0xdd),
        BrightCyan => Color32::from_rgb(0x56, 0xb6, 0xc2),
        BrightWhite => Color32::WHITE,
        AnsiColor(index) => one_dark_ansi_color(index),
        TrueColor { r, g, b } => Color32::from_rgb(r, g, b),
    }
}

fn one_dark_ansi_color(index: u8) -> Color32 {
    const PALETTE: [Color32; 16] = [
        Color32::from_rgb(0x28, 0x2c, 0x34),
        Color32::from_rgb(0xe0, 0x6c, 0x75),
        Color32::from_rgb(0x98, 0xc3, 0x79),
        Color32::from_rgb(0xe5, 0xc0, 0x7b),
        Color32::from_rgb(0x61, 0xaf, 0xef),
        Color32::from_rgb(0xc6, 0x78, 0xdd),
        Color32::from_rgb(0x56, 0xb6, 0xc2),
        Color32::from_rgb(0xab, 0xb2, 0xbf),
        Color32::from_rgb(0x5c, 0x63, 0x70),
        Color32::from_rgb(0xe0, 0x6c, 0x75),
        Color32::from_rgb(0x98, 0xc3, 0x79),
        Color32::from_rgb(0xe5, 0xc0, 0x7b),
        Color32::from_rgb(0x61, 0xaf, 0xef),
        Color32::from_rgb(0xc6, 0x78, 0xdd),
        Color32::from_rgb(0x56, 0xb6, 0xc2),
        Color32::WHITE,
    ];
    PALETTE
        .get(index as usize)
        .copied()
        .unwrap_or(Color32::from_rgb(0xab, 0xb2, 0xbf))
}
