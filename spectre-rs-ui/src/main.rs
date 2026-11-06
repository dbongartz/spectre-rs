use std::sync::{mpsc, Arc, Mutex};

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
    shared_output: Arc<Mutex<Output>>,
    compute_tx: mpsc::Sender<ComputeRequest>,
}

#[derive(Debug)]
struct Input {
    user: String,
    user_secret: String,
    pwtype: spectre_rs::PwType,
    sitename: String,
}

struct ComputeRequest {
    user: String,
    user_secret: Option<String>,
    sitename: String,
    pwtype: spectre_rs::PwType,
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

#[derive(Debug, Clone)]
struct Output {
    color: egui::Color32,
    identicon: egui::RichText,
    site_passwd: String,
}

impl Output {
    fn new() -> Self {
        Self {
            color: Color32::WHITE,
            site_passwd: String::new(),
            identicon: egui::RichText::new(""),
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
        let shared_output = Arc::new(Mutex::new(Output::new()));
        let (compute_tx, compute_rx) = mpsc::channel::<ComputeRequest>();
        let egui_ctx = cc.egui_ctx.clone();
        std::thread::spawn({
            let shared_output = shared_output.clone();
            let egui_ctx = egui_ctx.clone();
            move || {
                let mut user_key: Option<SecStr> = None;
                let mut cached_user = String::new();
                let mut identicon = RichText::new("");
                let mut identicon_color = Color32::WHITE;
                while let Ok(mut request) = compute_rx.recv() {
                    // Coalesce rapid edits so expensive derivation works on the newest state.
                    while let Ok(newer) = compute_rx.try_recv() {
                        if newer.user_secret.is_some() {
                            request.user_secret = newer.user_secret;
                        }
                        request.user = newer.user;
                        request.sitename = newer.sitename;
                        request.pwtype = newer.pwtype;
                    }

                    if let Some(secret) = request.user_secret.take() {
                        cached_user = request.user.clone();
                        if request.user.is_empty() || secret.is_empty() {
                            user_key = None;
                            identicon = RichText::new("");
                            identicon_color = Color32::WHITE;
                        } else {
                            let secret = SecStr::from(secret);
                            user_key = Some(spectre_rs::gen_user_key(
                                &request.user,
                                &secret,
                                spectre_rs::Scope::Authentication,
                            ));
                            let icon = spectre_rs::identicon::Identicon::from(
                                &secret,
                                &request.user,
                            );
                            if let colored::Color::TrueColor { r, g, b } =
                                into_truecolor(icon.get_ansi_color())
                            {
                                identicon_color = Color32::from_rgb(r, g, b);
                            }
                            identicon = RichText::new(std::format!(
                                "{}{}{}{}",
                                icon.left_arm, icon.body, icon.right_arm, icon.accessory
                            ))
                            .size(20.0)
                            .color(identicon_color);
                        }
                    } else if cached_user != request.user {
                        // Username is part of the scrypt salt, so it requires a fresh key.
                        user_key = None;
                    }

                    let mut output = Output::new();
                    if let Some(key) = user_key.as_ref().filter(|_| !request.user.is_empty()) {
                        if !request.sitename.is_empty() {
                            let seed = spectre_rs::gen_site_seed(
                                &request.sitename,
                                key,
                                spectre_rs::Scope::Authentication,
                                1,
                            );
                            let password = spectre_rs::gen_site_password(&seed, request.pwtype);
                            output.site_passwd = std::str::from_utf8(password.unsecure())
                                .unwrap()
                                .to_owned();
                        }
                    }

                    {
                        let mut current = shared_output.lock().unwrap();
                        current.site_passwd = output.site_passwd;
                        current.identicon = identicon.clone();
                        current.color = identicon_color;
                    }
                    egui_ctx.request_repaint();
                }
            }
        });

        Self {
            input,
            shared_output,
            compute_tx,
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add(egui::Label::new(egui::RichText::new(APP_TITLE).heading()));

                let output = self.shared_output.lock().unwrap();

                let username =
                    ui.add(egui::TextEdit::singleline(&mut self.input.user).hint_text("Username"));
                let secret = ui.add(
                    egui::TextEdit::singleline(&mut self.input.user_secret)
                        .password(true)
                        .hint_text("Password"),
                );

                ui.add(egui::Label::new(output.identicon.clone()));

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

                ui.label(&output.site_passwd);

                let credentials_changed = secret.changed() || username.changed();
                let site_changed = sitename.changed() || pwtype != self.input.pwtype;
                if pwtype != self.input.pwtype {
                    self.input.pwtype = pwtype;
                }
                if credentials_changed || site_changed {
                    let _ = self.compute_tx.send(ComputeRequest {
                        user: self.input.user.clone(),
                        user_secret: credentials_changed.then(|| self.input.user_secret.clone()),
                        sitename: self.input.sitename.clone(),
                        pwtype: self.input.pwtype,
                    });
                }
                drop(output);
            });
        });
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
