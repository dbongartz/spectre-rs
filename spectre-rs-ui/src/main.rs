use std::sync::mpsc;

use egui::{Color32, RichText};
use secstr::SecStr;

#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> eframe::Result {
    env_logger::init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 300.0])
            .with_min_inner_size([300.0, 220.0]),
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
    site_passwd: String,
    identicon: RichText,
    identicon_color: Color32,
}

#[derive(Debug)]
struct Input {
    user: String,
    user_secret: String,
    pwtype: spectre_rs::PwType,
    sitename: String,
}

struct DeriveRequest {
    revision: u64,
    user: String,
    user_secret: String,
}

struct DerivedKey {
    revision: u64,
    user_key: Option<SecStr>,
}

impl Input {
    fn new() -> Self {
        Self {
            user: String::new(),
            user_secret: String::new(),
            sitename: String::new(),
            pwtype: spectre_rs::PwType::Medium,
        }
    }
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
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

                    let user_key = if latest.user.is_empty() || latest.user_secret.is_empty() {
                        None
                    } else {
                        let secret = SecStr::from(latest.user_secret);
                        Some(spectre_rs::gen_user_key(
                            &latest.user,
                            &secret,
                            spectre_rs::Scope::Authentication,
                        ))
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
            site_passwd: String::new(),
            identicon: RichText::new(""),
            identicon_color: Color32::WHITE,
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        while let Ok(derived) = self.derived_rx.try_recv() {
            if derived.revision == self.derivation_revision {
                self.user_key = derived.user_key;
                self.update_site_password();
            }
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add(egui::Label::new(egui::RichText::new(APP_TITLE).heading()));

                let username =
                    ui.add(egui::TextEdit::singleline(&mut self.input.user).hint_text("Username"));
                let secret = ui.add(
                    egui::TextEdit::singleline(&mut self.input.user_secret)
                        .password(true)
                        .hint_text("Password"),
                );

                let mut pwtype = self.input.pwtype;
                let _cbox = egui::ComboBox::from_label("Type")
                    .selected_text(format!("{pwtype:?}"))
                    .width(100.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut pwtype, spectre_rs::PwType::Medium, "Medium");
                        ui.selectable_value(&mut pwtype, spectre_rs::PwType::Long, "Long");
                        ui.selectable_value(&mut pwtype, spectre_rs::PwType::Basic, "Basic");
                        ui.selectable_value(&mut pwtype, spectre_rs::PwType::Pin, "Pin");
                    });

                let sitename =
                    ui.add(egui::TextEdit::singleline(&mut self.input.sitename).hint_text("Sitename"));

                let credentials_changed = secret.changed() || username.changed();
                let site_changed = sitename.changed() || pwtype != self.input.pwtype;
                if pwtype != self.input.pwtype {
                    self.input.pwtype = pwtype;
                }
                if credentials_changed {
                    self.derivation_revision = self.derivation_revision.wrapping_add(1);
                    self.user_key = None;
                    self.site_passwd.clear();
                    self.update_identicon();
                    let _ = self.derive_tx.send(DeriveRequest {
                        revision: self.derivation_revision,
                        user: self.input.user.clone(),
                        user_secret: self.input.user_secret.clone(),
                    });
                } else if site_changed {
                    self.update_site_password();
                }

                ui.add(egui::Label::new(self.identicon.clone()));
                ui.label(&self.site_passwd);
            });
        });
    }
}

impl App {
    fn update_site_password(&mut self) {
        self.site_passwd = match (&self.user_key, self.input.sitename.is_empty()) {
            (Some(user_key), false) => {
                let seed = spectre_rs::gen_site_seed(
                    &self.input.sitename,
                    user_key,
                    spectre_rs::Scope::Authentication,
                    1,
                );
                let password = spectre_rs::gen_site_password(&seed, self.input.pwtype);
                std::str::from_utf8(password.unsecure()).unwrap().to_owned()
            }
            _ => String::new(),
        };
    }

    fn update_identicon(&mut self) {
        if self.input.user.is_empty() || self.input.user_secret.is_empty() {
            self.identicon = RichText::new("");
            self.identicon_color = Color32::WHITE;
            return;
        }

        let secret = SecStr::from(self.input.user_secret.clone());
        let icon = spectre_rs::identicon::Identicon::from(&secret, &self.input.user);
        if let colored::Color::TrueColor { r, g, b } = into_truecolor(icon.get_ansi_color()) {
            self.identicon_color = Color32::from_rgb(r, g, b);
        }
        self.identicon = RichText::new(std::format!(
            "{}{}{}{}",
            icon.left_arm, icon.body, icon.right_arm, icon.accessory
        ))
        .size(20.0)
        .color(self.identicon_color);
    }
}

fn into_truecolor(color: colored::Color) -> colored::Color {
    use colored::Color::*;
    match color {
        Black => TrueColor { r: 0, g: 0, b: 0 },
        Red => TrueColor { r: 205, g: 0, b: 0 },
        Green => TrueColor { r: 0, g: 205, b: 0 },
        Yellow => TrueColor {
            r: 205,
            g: 205,
            b: 0,
        },
        Blue => TrueColor { r: 0, g: 0, b: 238 },
        Magenta => TrueColor {
            r: 205,
            g: 0,
            b: 205,
        },
        Cyan => TrueColor {
            r: 0,
            g: 205,
            b: 205,
        },
        White => TrueColor {
            r: 229,
            g: 229,
            b: 229,
        },
        BrightBlack => TrueColor {
            r: 127,
            g: 127,
            b: 127,
        },
        BrightRed => TrueColor { r: 255, g: 0, b: 0 },
        BrightGreen => TrueColor { r: 0, g: 255, b: 0 },
        BrightYellow => TrueColor {
            r: 255,
            g: 255,
            b: 0,
        },
        BrightBlue => TrueColor {
            r: 92,
            g: 92,
            b: 255,
        },
        BrightMagenta => TrueColor {
            r: 255,
            g: 0,
            b: 255,
        },
        BrightCyan => TrueColor {
            r: 0,
            g: 255,
            b: 255,
        },
        BrightWhite => TrueColor {
            r: 255,
            g: 255,
            b: 255,
        },
        TrueColor { r, g, b } => TrueColor { r, g, b },
        AnsiColor(_) => todo!("AnsiColor to rgb not implemented."),
    }
}
