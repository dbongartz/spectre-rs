//! A desktop app that derives Spectre site passwords as you type.

mod app;
mod clipboard;
mod derive;
mod fonts;
mod state;
mod theme;
mod widgets;

#[cfg(all(feature = "dev-inspection", not(debug_assertions)))]
compile_error!("the dev-inspection feature is only available in debug builds");

const APP_TITLE: &str = "Spectre Password Manager";

#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> eframe::Result {
    env_logger::init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("spectre-rs-gui")
            .with_icon(app_icon())
            // In points: eframe scales it by the zoom restored from storage. On the first
            // launch that is still 1.0, and `App::keep_window_size` corrects it on the first
            // frame.
            .with_inner_size(theme::WINDOW_SIZE)
            .with_resizable(false),
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        APP_TITLE,
        native_options,
        Box::new(|cc| {
            #[cfg(feature = "dev-inspection")]
            attach_inspection(&cc.egui_ctx);
            Ok(Box::new(app::App::new(cc)))
        }),
    )
}

fn app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/spectre-rs-gui.png"))
        .expect("embedded application icon must be a valid PNG")
}

/// Serves the UI to `egui-mcp` and similar tools when `SPECTRE_UI_INSPECTION` is set.
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
