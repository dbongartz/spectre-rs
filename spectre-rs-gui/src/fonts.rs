//! The bundled fonts, and the font families the UI draws with.

use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};

/// Fira Mono Medium: a dotted zero and distinct `l`/`1`/`I`, so passwords read unambiguously.
/// Also the first proportional fallback, for the identicon glyphs it carries. Subset to
/// everything but the Nerd Font icons; see `assets/fonts/README.md`.
const FIRA_MONO_MEDIUM: &[u8] = include_bytes!("../assets/fonts/FiraMonoNerdFont-Medium-Text.otf");
const PASSWORD_FAMILY: &str = "password";

/// Nerd Font with proportional icon widths. The monospace variant squeezes icons into one cell
/// and lets them overflow it, which puts them visibly off-center. Subset to the [`icons`] below.
const ICON_FONT: (&str, &[u8]) = (
    "icons",
    include_bytes!("../assets/fonts/FiraMonoNerdFontPropo-Medium-Icons.otf"),
);

/// The glyphs drawn with [`icon`]. The icon font holds only these, so a new one must be added
/// to its subset too; a test checks that it is.
pub mod icons {
    pub const USER: &str = "\u{f007}";
    pub const KEY: &str = "\u{f084}";
    pub const GLOBE: &str = "\u{f0ac}";
    pub const SLIDERS: &str = "\u{f1de}";
    pub const EYE: &str = "\u{f06e}";
    pub const EYE_SLASH: &str = "\u{f070}";
    pub const RETURN: &str = "\u{23ce}";

    #[cfg(test)]
    pub const ALL: [&str; 7] = [USER, KEY, GLOBE, SLIDERS, EYE, EYE_SLASH, RETURN];
}

/// UI text font, subset to Latin; anything else falls back to egui's default fonts.
const TEXT_FONT: (&str, &[u8]) = (
    "fira_sans",
    include_bytes!("../assets/fonts/FiraSans-Regular-Latin.ttf"),
);

/// Fonts appended to the proportional family, in fallback order.
///
/// egui's default fonts (without the `monochrome_emoji_fonts` feature) cover none of the
/// identicon glyphs, so these must cover every one of them; see the test below.
/// The two `*-Identicon` files are subsets holding only the glyphs the others lack.
const FALLBACK_FONTS: &[(&str, &[u8])] = &[
    ("fira_mono_fallback", FIRA_MONO_MEDIUM),
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

pub fn install(ctx: &egui::Context) {
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
        ctx.add_font(FontInsert::new(
            name,
            egui::FontData::from_static(data),
            vec![InsertFontFamily {
                family,
                priority: FontPriority::Highest,
            }],
        ));
    }
    for &(name, data) in FALLBACK_FONTS {
        ctx.add_font(FontInsert::new(
            name,
            egui::FontData::from_static(data),
            vec![InsertFontFamily {
                family: egui::FontFamily::Proportional,
                priority: FontPriority::Lowest,
            }],
        ));
    }
}

pub fn icon(size: f32) -> egui::FontId {
    egui::FontId::new(size, egui::FontFamily::Name(ICON_FONT.0.into()))
}

pub fn password(size: f32) -> egui::FontId {
    egui::FontId::new(size, egui::FontFamily::Name(PASSWORD_FAMILY.into()))
}

#[cfg(test)]
mod tests {
    use skrifa::{FontRef, MetadataProvider};
    use spectre_rs_core::identicon::{
        IDENTICON_ACCESSORIES, IDENTICON_BODIES, IDENTICON_LEFT_ARMS, IDENTICON_RIGHT_ARMS,
    };

    fn missing_chars(font: &[u8], chars: impl IntoIterator<Item = char>) -> Vec<char> {
        let font = FontRef::new(font).unwrap();
        chars
            .into_iter()
            .filter(|&c| font.charmap().map(c).is_none())
            .collect()
    }

    #[test]
    fn icon_font_covers_every_icon() {
        let missing = missing_chars(
            super::ICON_FONT.1,
            super::icons::ALL.iter().flat_map(|icon| icon.chars()),
        );
        assert!(missing.is_empty(), "the icon font lacks: {missing:?}");
    }

    /// Every character a password can contain is printable ASCII.
    #[test]
    fn password_font_covers_printable_ascii() {
        let missing = missing_chars(super::FIRA_MONO_MEDIUM, ' '..='~');
        assert!(missing.is_empty(), "the password font lacks: {missing:?}");
    }

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
