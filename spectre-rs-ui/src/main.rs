use std::sync::{Arc, Condvar, Mutex};

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
    shared_input: Arc<Mutex<Input>>,
    shared_output: Arc<Mutex<Output>>,
    signal: Arc<(Mutex<u8>, Condvar)>,
}

#[derive(Debug, Clone)]
struct Input {
    user: String,
    user_secret: String,
    pwtype: spectre_rs::PwType,
    sitename: String,
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

        let shared_input = Arc::new(Mutex::new(Input::new()));
        let shared_output = Arc::new(Mutex::new(Output::new()));

        let signal = Arc::new((Mutex::new(0), Condvar::new()));

        std::thread::spawn({
            let shared_input = shared_input.clone();
            let shared_output = shared_output.clone();
            let signal = signal.clone();
            move || {
                loop {
                    {
                        let mut new_input = signal
                            .1
                            .wait_while(signal.0.lock().unwrap(), |&mut new_input| {
                                new_input & 0b01 != 0b01
                            })
                            .unwrap();
                        *new_input &= 0b10;
                    }
                    let input = shared_input.lock().unwrap().clone();

                    let ready_for_identicon =
                        !(input.user.is_empty() || input.user_secret.is_empty());
                    let ready_for_pw = ready_for_identicon && !input.sitename.is_empty();

                    if ready_for_pw {
                        if ready_for_pw {
                            let sec_pw = SecStr::from(input.user_secret);
                            let site_passwd = spectre_rs::get_site_password(
                                &input.user,
                                &sec_pw,
                                &input.sitename,
                                1,
                                input.pwtype,
                                spectre_rs::Scope::Authentication,
                            );

                            let site_passwd = std::str::from_utf8(site_passwd.unsecure())
                                .unwrap()
                                .to_string();
                            shared_output.lock().unwrap().site_passwd = site_passwd;
                        } else {
                            shared_output.lock().unwrap().site_passwd.clear();
                        };
                    }
                }
            }
        });

        std::thread::spawn({
            let shared_input = shared_input.clone();
            let shared_output = shared_output.clone();
            let signal = signal.clone();
            move || {
                loop {
                    {
                        let mut new_input = signal
                            .1
                            .wait_while(signal.0.lock().unwrap(), |&mut new_input| {
                                new_input & 0b10 != 0b10
                            })
                            .unwrap();
                        *new_input &= 0b01;
                    }
                    let input = shared_input.lock().unwrap().clone();

                    let ready_for_identicon =
                        !(input.user.is_empty() || input.user_secret.is_empty());

                    if ready_for_identicon {
                        let sec_pw = SecStr::from(input.user_secret);

                        let identicon =
                            spectre_rs::identicon::Identicon::from(&sec_pw, &input.user);

                        let color = if let colored::Color::TrueColor { r, g, b } =
                            into_truecolor(identicon.get_ansi_color())
                        {
                            Some(Color32::from_rgb(r, g, b))
                        } else {
                            None
                        }
                        .unwrap();

                        let identicon = egui::RichText::new(std::format!(
                            "{}{}{}{}",
                            identicon.left_arm,
                            identicon.body,
                            identicon.right_arm,
                            identicon.accessory
                        ))
                        .size(20.0)
                        .color(color);

                        let mut lock = shared_output.lock().unwrap();
                        lock.color = color;
                        lock.identicon = identicon;
                    } else {
                        let mut lock = shared_output.lock().unwrap();
                        lock.identicon = RichText::new("");
                    };
                }
            }
        });

        Self {
            shared_input,
            shared_output,
            signal,
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add(egui::Label::new(egui::RichText::new(APP_TITLE).heading()));

                let mut input = { self.shared_input.lock().unwrap().clone() };
                let output = { self.shared_output.lock().unwrap().clone() };

                let username =
                    ui.add(egui::TextEdit::singleline(&mut input.user).hint_text("Username"));
                let secret = ui.add(
                    egui::TextEdit::singleline(&mut input.user_secret)
                        .password(true)
                        .hint_text("Password"),
                );

                ui.add(egui::Label::new(output.identicon.clone()));

                let mut pwtype = input.pwtype;
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
                    ui.add(egui::TextEdit::singleline(&mut input.sitename).hint_text("Sitename"));

                ui.label(&output.site_passwd);

                let mut mask = 0b00;
                if secret.changed() || username.changed() {
                    mask |= 0b10;
                }
                if sitename.changed() || pwtype != input.pwtype {
                    input.pwtype = pwtype;
                    mask |= 0b01;
                }
                if mask != 0b00 {
                    {
                        *self.shared_input.lock().unwrap() = input.clone();
                        *self.signal.0.lock().unwrap() = mask;
                    }
                    self.signal.1.notify_all();
                }
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
