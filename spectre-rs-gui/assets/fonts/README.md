# Bundled fonts

All fonts are licensed under the SIL Open Font License 1.1; each `*-OFL.txt` holds the license
with the copyright of the fonts it covers. Most files are subsets, to keep the binary small.
`spectre-rs-gui/src/fonts.rs` says what each one is used for, and its tests check that the subsets
still cover every glyph the app draws.

| File | Source | License |
| --- | --- | --- |
| `FiraSans-Regular-Latin.ttf` | [Fira Sans](https://github.com/mozilla/Fira) Regular, subset to Latin | `FiraSans-OFL.txt` |
| `FiraMonoNerdFont-Medium-Text.otf` | [FiraMono Nerd Font](https://github.com/ryanoasis/nerd-fonts) Medium, without the Nerd Font icons | `FiraMono-OFL.txt` |
| `FiraMonoNerdFontPropo-Medium-Icons.otf` | FiraMono Nerd Font Propo Medium, only the icons the UI uses | `FiraMono-OFL.txt` |
| `NotoSansSymbols2-Regular.ttf` | [Noto Sans Symbols 2](https://github.com/notofonts/symbols) Regular | `NotoSansSymbols2-OFL.txt` |
| `NotoSansSymbols-Identicon.ttf` | [Noto Sans Symbols](https://github.com/notofonts/symbols) Regular, only the identicon glyphs no other font here has | `NotoSansSymbols-OFL.txt` |
| `NotoEmoji-Identicon.ttf` | [Noto Emoji](https://github.com/googlefonts/noto-emoji) (monochrome), only the identicon glyphs no other font here has | `NotoEmoji-OFL.txt` |

The icons in the Nerd Font files come from [Font Awesome](https://fontawesome.com) 4, whose font is
also licensed under the SIL Open Font License 1.1.

## Making the Fira Mono subsets

With `pyftsubset` from [fontTools](https://github.com/fonttools/fonttools), starting from
`FiraMonoNerdFont-Medium.otf` and `FiraMonoNerdFontPropo-Medium.otf` of a Nerd Fonts release:

```sh
# Everything except the Private Use Area, where Nerd Fonts puts its icons.
pyftsubset FiraMonoNerdFont-Medium.otf \
  --unicodes='U+0000-DFFF,U+F900-FFFF' \
  --layout-features='*' --name-IDs='*' --name-languages='*' --notdef-outline \
  --output-file=FiraMonoNerdFont-Medium-Text.otf

# Only the icons in `fonts::icons`; add a code point here when adding an icon there.
pyftsubset FiraMonoNerdFontPropo-Medium.otf \
  --unicodes='U+23CE,U+F007,U+F06E,U+F070,U+F084,U+F0AC,U+F1DE' \
  --name-IDs='*' --name-languages='*' --notdef-outline \
  --output-file=FiraMonoNerdFontPropo-Medium-Icons.otf
```
