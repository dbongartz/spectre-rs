//! The bundled fonts, and the font families the UI draws with.

use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};

/// Fira Mono Medium: a dotted zero and distinct `l`/`1`/`I`, so passwords read unambiguously.
/// Also the first proportional fallback, for the icon glyphs it carries.
const FIRA_MONO_MEDIUM: &[u8] = include_bytes!("../assets/fonts/FiraMonoNerdFont-Medium.otf");
const PASSWORD_FAMILY: &str = "password";

/// Nerd Font with proportional icon widths. The monospace variant squeezes icons into one cell
/// and lets them overflow it, which puts them visibly off-center.
const ICON_FONT: (&str, &[u8]) = (
    "icons",
    include_bytes!("../assets/fonts/FiraMonoNerdFontPropo-Medium.otf"),
);

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
