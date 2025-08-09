use egui::{Color32, Layout};
use secstr::SecStr;

#[cfg(not(target_arch = "wasm32"))]
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
    user: String,
    user_secret: String,
    sitename: String,
    identicon: egui::RichText,
    color: egui::Color32,
    site_passwd: String,
    pwtype: spectre_rs::PwType,
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

        Self {
            user: String::new(),
            user_secret: String::new(),
            sitename: String::new(),
            identicon: egui::RichText::new(""),
            color: Color32::WHITE,
            site_passwd: String::new(),
            pwtype: spectre_rs::PwType::Medium,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add(egui::Label::new(egui::RichText::new(APP_TITLE).heading()));

                let user = ui.add(egui::TextEdit::singleline(&mut self.user).hint_text("Username"));
                let pw = ui.add(
                    egui::TextEdit::singleline(&mut self.user_secret)
                        .password(true)
                        .hint_text("Password"),
                );

                ui.add(egui::Label::new(self.identicon.clone()));

                let mut pwtype = self.pwtype;
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
                    ui.add(egui::TextEdit::singleline(&mut self.sitename).hint_text("Sitename"));

                ui.label(&self.site_passwd);

                let pwtype_changed = self.pwtype != pwtype;
                let inputs_changed =
                    user.changed() || pw.changed() || sitename.changed() || pwtype_changed;
                let ready_for_identicon = !(self.user.is_empty() || self.user_secret.is_empty());
                let ready_for_pw = ready_for_identicon && !self.sitename.is_empty();

                if inputs_changed {
                    if pwtype_changed {
                        self.pwtype = pwtype;
                    }

                    if ready_for_identicon {
                        let sec_pw = SecStr::from(self.user_secret.to_owned());

                        let identicon = spectre_rs::identicon::Identicon::from(&sec_pw, &self.user);

                        self.color = if let colored::Color::TrueColor { r, g, b } =
                            into_truecolor(identicon.get_ansi_color())
                        {
                            Some(Color32::from_rgb(r, g, b))
                        } else {
                            None
                        }
                        .unwrap();

                        self.identicon = egui::RichText::new(std::format!(
                            "{}{}{}{}",
                            identicon.left_arm,
                            identicon.body,
                            identicon.right_arm,
                            identicon.accessory
                        ))
                        .size(20.0)
                        .color(self.color);
                    } else {
                        self.identicon = egui::RichText::new("");
                    }

                    if ready_for_pw {
                        self.pwtype = pwtype;
                        let sec_pw = SecStr::from(self.user_secret.to_owned());
                        let site_passwd = spectre_rs::get_site_password(
                            &self.user,
                            &sec_pw,
                            &self.sitename,
                            1,
                            self.pwtype,
                            spectre_rs::Scope::Authentication,
                        );

                        self.site_passwd = std::str::from_utf8(site_passwd.unsecure())
                            .unwrap()
                            .to_string();
                    } else {
                        self.site_passwd.clear();
                    }
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
    }
}
