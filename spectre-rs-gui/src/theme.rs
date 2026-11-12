//! Sizes, colors and the egui style of the app: a dark or light panel with borderless fields and
//! flat, rounded controls.

use egui::{Color32, Theme, ThemePreference};
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
/// The theme switch in the lower left corner, including the inset around its highlight.
pub const THEME_BUTTON_SIZE: f32 = 36.0;

/// The colors of one theme. Contrast ratios noted below are against the color the text sits on.
pub struct Palette {
    pub panel: Color32,
    pub field: Color32,
    pub control: Color32,
    pub control_hover: Color32,
    pub control_active: Color32,
    pub divider: Color32,
    pub chip: Color32,
    pub icon: Color32,
    pub disabled_icon: Color32,
    /// Placeholders double as field labels, so they need full text contrast (5.3:1 or more).
    pub placeholder: Color32,
    pub focus: Color32,
    /// The selected dropdown row and text selections.
    pub selection: Color32,
    /// The type details on the selected dropdown row; about 5:1 there.
    pub selected_detail: Color32,
    pub muted_text: Color32,
    pub version: Color32,
    pub text: Color32,
    pub password: Color32,
    /// A missing password's placeholder, or a stale one while its replacement is derived.
    pub inactive_password: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_active: Color32,
    pub accent_text: Color32,
    pub copied: Color32,
    pub copied_text: Color32,
    /// The identicon colors, in [`IdenticonColor`] order, before [`Palette::identicon_color`]
    /// blends them toward `identicon_blend`.
    identicon: [Color32; 7],
    identicon_blend: (Color32, f32),
}

pub const DARK: Palette = Palette {
    panel: Color32::from_rgb(0x1c, 0x1c, 0x1c),
    field: Color32::from_rgb(0x0b, 0x0b, 0x0b),
    control: Color32::from_rgb(0x2f, 0x2f, 0x2f),
    control_hover: Color32::from_rgb(0x3a, 0x3a, 0x3a),
    control_active: Color32::from_rgb(0x44, 0x44, 0x44),
    divider: Color32::from_rgb(0x44, 0x44, 0x44),
    chip: Color32::from_rgb(0x1e, 0x22, 0x24),
    icon: Color32::from_rgb(0x8a, 0x8a, 0x8a),
    disabled_icon: Color32::from_gray(90),
    placeholder: Color32::from_gray(0x8c),
    focus: Color32::from_rgb(0x8c, 0xc4, 0xf2),
    // egui's own dark selection color.
    selection: Color32::from_rgb(0, 92, 128),
    selected_detail: Color32::from_rgb(0xcc, 0xe0, 0xee),
    muted_text: Color32::from_rgb(0x9a, 0x9a, 0x9a),
    version: Color32::from_gray(105),
    text: Color32::from_rgb(0xe8, 0xe8, 0xe8),
    password: Color32::from_rgb(0xf0, 0xf0, 0xf0),
    inactive_password: Color32::from_gray(110),
    accent: Color32::from_rgb(0x2b, 0x6c, 0xa3),
    accent_hover: Color32::from_rgb(0x35, 0x7a, 0xb4),
    accent_active: Color32::from_rgb(0x24, 0x5d, 0x8d),
    accent_text: Color32::WHITE,
    copied: Color32::from_rgb(37, 61, 47),
    copied_text: Color32::from_rgb(166, 220, 185),
    // One Dark.
    identicon: [
        Color32::from_rgb(0xe0, 0x6c, 0x75),
        Color32::from_rgb(0x98, 0xc3, 0x79),
        Color32::from_rgb(0xe5, 0xc0, 0x7b),
        Color32::from_rgb(0x61, 0xaf, 0xef),
        Color32::from_rgb(0xc6, 0x78, 0xdd),
        Color32::from_rgb(0x56, 0xb6, 0xc2),
        Color32::from_rgb(0xab, 0xb2, 0xbf),
    ],
    identicon_blend: (Color32::from_gray(150), 0.35),
};

pub const LIGHT: Palette = Palette {
    panel: Color32::from_rgb(0xf2, 0xf2, 0xf2),
    field: Color32::WHITE,
    control: Color32::from_rgb(0xe2, 0xe2, 0xe2),
    control_hover: Color32::from_rgb(0xd6, 0xd6, 0xd6),
    control_active: Color32::from_rgb(0xca, 0xca, 0xca),
    divider: Color32::from_rgb(0xc4, 0xc4, 0xc4),
    chip: Color32::from_rgb(0xe6, 0xea, 0xed),
    icon: Color32::from_rgb(0x6e, 0x6e, 0x6e),
    disabled_icon: Color32::from_gray(180),
    placeholder: Color32::from_gray(0x6b),
    focus: Color32::from_rgb(0x1f, 0x5f, 0x99),
    selection: Color32::from_rgb(0xcd, 0xe4, 0xf7),
    selected_detail: Color32::from_rgb(0x3d, 0x63, 0x85),
    muted_text: Color32::from_rgb(0x66, 0x66, 0x66),
    version: Color32::from_gray(150),
    text: Color32::from_rgb(0x1e, 0x1e, 0x1e),
    password: Color32::from_rgb(0x14, 0x14, 0x14),
    inactive_password: Color32::from_gray(165),
    accent: Color32::from_rgb(0x2b, 0x6c, 0xa3),
    accent_hover: Color32::from_rgb(0x35, 0x7a, 0xb4),
    accent_active: Color32::from_rgb(0x24, 0x5d, 0x8d),
    accent_text: Color32::WHITE,
    copied: Color32::from_rgb(0xd3, 0xec, 0xdb),
    copied_text: Color32::from_rgb(0x1e, 0x5b, 0x34),
    // One Light.
    identicon: [
        Color32::from_rgb(0xe4, 0x56, 0x49),
        Color32::from_rgb(0x50, 0xa1, 0x4f),
        Color32::from_rgb(0xc1, 0x84, 0x01),
        Color32::from_rgb(0x40, 0x78, 0xf2),
        Color32::from_rgb(0xa6, 0x26, 0xa4),
        Color32::from_rgb(0x01, 0x84, 0xbc),
        Color32::from_rgb(0x38, 0x3a, 0x42),
    ],
    identicon_blend: (Color32::from_gray(110), 0.25),
};

impl Palette {
    pub fn of(theme: Theme) -> &'static Self {
        match theme {
            Theme::Dark => &DARK,
            Theme::Light => &LIGHT,
        }
    }

    /// The identicon's color as drawn inside the secret field: the One Dark or One Light take
    /// on it, blended toward gray so it sits quietly there.
    pub fn identicon_color(&self, color: IdenticonColor) -> Color32 {
        let index = match color {
            IdenticonColor::Red => 0,
            IdenticonColor::Green => 1,
            IdenticonColor::Yellow => 2,
            IdenticonColor::Blue => 3,
            IdenticonColor::Magenta => 4,
            IdenticonColor::Cyan => 5,
            IdenticonColor::White => 6,
        };
        let (gray, amount) = self.identicon_blend;
        self.identicon[index].lerp_to_gamma(gray, amount)
    }
}

/// The palette of the theme `ui` is drawn in.
pub fn colors(ui: &egui::Ui) -> &'static Palette {
    if ui.visuals().dark_mode {
        &DARK
    } else {
        &LIGHT
    }
}

/// Styles both themes. Which one shows is the user's [`ThemePreference`], which egui keeps
/// with the rest of its memory across launches; see [`next_preference`].
pub fn apply(ctx: &egui::Context) {
    for theme in [Theme::Dark, Theme::Light] {
        let colors = Palette::of(theme);
        ctx.style_mut_of(theme, |style| {
            let visuals = &mut style.visuals;
            visuals.panel_fill = colors.panel;
            visuals.window_fill = colors.panel;
            visuals.extreme_bg_color = colors.field;
            visuals.window_corner_radius = CORNER_RADIUS.into();
            visuals.menu_corner_radius = CORNER_RADIUS.into();
            visuals.weak_text_color = Some(colors.placeholder);
            visuals.selection.bg_fill = colors.selection;
            visuals.selection.stroke.color = colors.focus;

            let widgets = &mut visuals.widgets;
            for (state, fill) in [
                (&mut widgets.inactive, colors.control),
                (&mut widgets.hovered, colors.control_hover),
                (&mut widgets.active, colors.control_active),
                (&mut widgets.open, colors.control_hover),
            ] {
                state.bg_fill = fill;
                state.weak_bg_fill = fill;
                state.corner_radius = CORNER_RADIUS.into();
                state.expansion = 0.0;
            }
            widgets.inactive.bg_stroke = egui::Stroke::NONE;
            widgets.inactive.fg_stroke.color = colors.text;
            widgets.hovered.bg_stroke = egui::Stroke::new(1.0, colors.divider);
            widgets.active.bg_stroke = egui::Stroke::NONE;
            widgets.open.bg_stroke = egui::Stroke::NONE;

            style.spacing.interact_size.y = FIELD_HEIGHT;
            style.spacing.button_padding = egui::vec2(FIELD_PADDING.into(), 4.0);
        });
    }
}

/// The preference the theme switch moves to from `current`: system, then dark, then light.
pub fn next_preference(current: ThemePreference) -> ThemePreference {
    match current {
        ThemePreference::System => ThemePreference::Dark,
        ThemePreference::Dark => ThemePreference::Light,
        ThemePreference::Light => ThemePreference::System,
    }
}

/// How the theme switch shows and announces `preference`.
pub fn preference_name(preference: ThemePreference) -> &'static str {
    match preference {
        ThemePreference::System => "System",
        ThemePreference::Dark => "Dark",
        ThemePreference::Light => "Light",
    }
}
