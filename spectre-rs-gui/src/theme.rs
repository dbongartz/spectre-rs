//! Sizes, colors and the egui style of the app: a dark panel with borderless fields and flat,
//! rounded controls.

use egui::Color32;
use spectre_rs_core::identicon::IdenticonColor;

/// Window content size in egui points. The window grows with the zoom instead of reflowing.
pub const WINDOW_SIZE: egui::Vec2 = egui::vec2(436.0, 420.0);
pub const DEFAULT_ZOOM: f32 = 1.1;

pub const LABEL_WIDTH: f32 = 28.0;
pub const FIELD_GAP: f32 = 12.0;
pub const ROW_GAP: f32 = 12.0;
/// Horizontal text inset inside fields and buttons.
pub const FIELD_PADDING: i8 = 12;
pub const FIELD_WIDTH: f32 = 344.0;
pub const FIELD_HEIGHT: f32 = 44.0;
pub const TYPE_WIDTH: f32 = 204.0;
pub const CORNER_RADIUS: u8 = 9;
pub const ICON_SIZE: f32 = 16.0;
pub const TEXT_SIZE: f32 = 16.0;
pub const HINT_SIZE: f32 = 12.0;
pub const POPUP_ROW_HEIGHT: f32 = 28.0;
pub const PASSWORD_SIZE: f32 = 36.0;
/// Room left on either side of the password before it is shrunk to fit.
pub const PASSWORD_MARGIN: f32 = 20.0;
pub const COPY_BUTTON_WIDTH: f32 = 184.0;
pub const IDENTICON_SIZE: f32 = 17.0;
pub const IDENTICON_CHIP_MIN_WIDTH: f32 = 47.0;
/// Room at the right of the secret field for the identicon chip and eye toggle.
pub const SECRET_TRAILING_WIDTH: f32 = 112.0;
pub const STEPPER_SEGMENT: f32 = 40.0;
/// Gap between a field's edge and the rounded hover highlight of a button inside it.
pub const HIGHLIGHT_INSET: f32 = 6.0;
pub const HIGHLIGHT_RADIUS: u8 = 6;

pub const PANEL_COLOR: Color32 = Color32::from_rgb(0x1c, 0x1c, 0x1c);
pub const FIELD_COLOR: Color32 = Color32::from_rgb(0x0b, 0x0b, 0x0b);
pub const CONTROL_COLOR: Color32 = Color32::from_rgb(0x2f, 0x2f, 0x2f);
pub const CONTROL_HOVER_COLOR: Color32 = Color32::from_rgb(0x3a, 0x3a, 0x3a);
pub const CONTROL_ACTIVE_COLOR: Color32 = Color32::from_rgb(0x44, 0x44, 0x44);
pub const DIVIDER_COLOR: Color32 = Color32::from_rgb(0x44, 0x44, 0x44);
pub const CHIP_COLOR: Color32 = Color32::from_rgb(0x1e, 0x22, 0x24);
pub const ICON_COLOR: Color32 = Color32::from_rgb(0x8a, 0x8a, 0x8a);
pub const DISABLED_ICON_COLOR: Color32 = Color32::from_gray(90);
pub const PLACEHOLDER_COLOR: Color32 = Color32::from_gray(0x8c);
pub const FOCUS_COLOR: Color32 = Color32::from_rgb(0x8c, 0xc4, 0xf2);
/// The type details on the selected (blue) dropdown row; about 5.7:1 there.
pub const SELECTED_DETAIL_COLOR: Color32 = Color32::from_rgb(0xcc, 0xe0, 0xee);
pub const MUTED_TEXT_COLOR: Color32 = Color32::from_rgb(0x9a, 0x9a, 0x9a);
pub const VERSION_COLOR: Color32 = Color32::from_gray(105);
pub const TEXT_COLOR: Color32 = Color32::from_rgb(0xe8, 0xe8, 0xe8);
pub const PASSWORD_COLOR: Color32 = Color32::from_rgb(0xf0, 0xf0, 0xf0);
/// A missing password's placeholder, or a stale one while its replacement is derived.
pub const INACTIVE_PASSWORD_COLOR: Color32 = Color32::from_gray(110);
pub const ACCENT_COLOR: Color32 = Color32::from_rgb(0x2b, 0x6c, 0xa3);
pub const ACCENT_HOVER_COLOR: Color32 = Color32::from_rgb(0x35, 0x7a, 0xb4);
pub const ACCENT_ACTIVE_COLOR: Color32 = Color32::from_rgb(0x24, 0x5d, 0x8d);
pub const ACCENT_TEXT_COLOR: Color32 = Color32::WHITE;
pub const COPIED_COLOR: Color32 = Color32::from_rgb(37, 61, 47);
pub const COPIED_TEXT_COLOR: Color32 = Color32::from_rgb(166, 220, 185);

pub fn apply(ctx: &egui::Context) {
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

/// The identicon's color as drawn inside the secret field: the One Dark palette's take on it,
/// blended toward gray so it sits quietly there.
pub fn identicon_color(color: IdenticonColor) -> Color32 {
    let color = match color {
        IdenticonColor::Red => Color32::from_rgb(0xe0, 0x6c, 0x75),
        IdenticonColor::Green => Color32::from_rgb(0x98, 0xc3, 0x79),
        IdenticonColor::Yellow => Color32::from_rgb(0xe5, 0xc0, 0x7b),
        IdenticonColor::Blue => Color32::from_rgb(0x61, 0xaf, 0xef),
        IdenticonColor::Magenta => Color32::from_rgb(0xc6, 0x78, 0xdd),
        IdenticonColor::Cyan => Color32::from_rgb(0x56, 0xb6, 0xc2),
        IdenticonColor::White => Color32::from_rgb(0xab, 0xb2, 0xbf),
    };
    color.lerp_to_gamma(Color32::from_gray(150), 0.35)
}
