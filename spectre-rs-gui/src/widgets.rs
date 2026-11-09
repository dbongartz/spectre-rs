//! Reusable controls, drawn in the app's theme.

use egui::{Color32, RichText};
use spectre_rs_core::PwType;

use crate::fonts;
use crate::theme::{
    CONTROL_ACTIVE_COLOR, CONTROL_COLOR, CONTROL_HOVER_COLOR, CORNER_RADIUS, DISABLED_ICON_COLOR,
    DIVIDER_COLOR, FIELD_HEIGHT, FIELD_PADDING, FOCUS_COLOR, HIGHLIGHT_INSET, HIGHLIGHT_RADIUS,
    HINT_SIZE, ICON_COLOR, ICON_SIZE, MUTED_TEXT_COLOR, POPUP_ROW_HEIGHT, SELECTED_DETAIL_COLOR,
    STEPPER_SEGMENT, TEXT_COLOR, TEXT_SIZE,
};

/// The icon in front of a form row. Screen readers announce it as `name`, the row's label; the
/// longer `hint` is its tooltip, so it never covers the field below the one being hovered.
pub fn row_icon(ui: &mut egui::Ui, icon: &str, name: &str, hint: &str) -> egui::Response {
    let response = ui
        .label(
            RichText::new(icon)
                .font(fonts::icon(ICON_SIZE))
                .color(ICON_COLOR),
        )
        .on_hover_text(hint);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, name));
    response
}

pub fn text_field<'t>(text: &'t mut String, hint: &str) -> egui::TextEdit<'t> {
    egui::TextEdit::singleline(text)
        .font(egui::FontId::proportional(TEXT_SIZE))
        .text_color(TEXT_COLOR)
        .margin(egui::Margin::symmetric(FIELD_PADDING, 0))
        .align(egui::Align2::LEFT_CENTER)
        .hint_text(hint)
}

/// Whether Enter was pressed to leave this single-line field.
pub fn submitted(response: &egui::Response) -> bool {
    response.lost_focus()
        && response
            .ctx
            .input(|input| input.key_pressed(egui::Key::Enter))
}

/// Drops the undo history egui keeps for a text field, so it holds no old copies of the text.
///
/// Called every frame, because egui adds a snapshot whenever the text has settled for a moment.
pub fn forget_undo_history(ctx: &egui::Context, id: egui::Id) {
    if let Some(mut state) = egui::TextEdit::load_state(ctx, id) {
        state.clear_undoer();
        state.store(ctx, id);
    }
}

pub fn password_type_selector(ui: &mut egui::Ui, pw_type: &mut PwType, width: f32) {
    let response = egui::ComboBox::from_id_salt("password_type")
        .selected_text(RichText::new(format!("{pw_type:?}")).size(TEXT_SIZE))
        .width(width)
        .show_ui(ui, |ui| {
            // Compact rows, so all six types fit below the field without scrolling.
            ui.spacing_mut().interact_size.y = POPUP_ROW_HEIGHT;
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                for (value, name, detail) in [
                    (PwType::Maximum, "Maximum", "20 · symbols"),
                    (PwType::Long, "Long", "14 · symbols"),
                    (PwType::Medium, "Medium", "8 · symbols"),
                    (PwType::Basic, "Basic", "8 · no symbols"),
                    (PwType::Short, "Short", "4 · no symbols"),
                    (PwType::Pin, "Pin", "4 · digits"),
                ] {
                    let selected = *pw_type == value;
                    let response =
                        ui.selectable_value(pw_type, value, RichText::new(name).size(TEXT_SIZE));
                    response.widget_info(|| {
                        egui::WidgetInfo::selected(
                            egui::Role::Button,
                            true,
                            selected,
                            format!("{name}, {detail}"),
                        )
                    });
                    // The length, right-aligned in muted text, so types compare at a glance.
                    let padding = ui.spacing().button_padding.x;
                    ui.painter().text(
                        egui::pos2(response.rect.right() - padding, response.rect.center().y),
                        egui::Align2::RIGHT_CENTER,
                        detail,
                        egui::FontId::proportional(HINT_SIZE + 1.0),
                        if selected {
                            SELECTED_DETAIL_COLOR
                        } else {
                            MUTED_TEXT_COLOR
                        },
                    );
                }
            });
        })
        .response
        .on_hover_text("Password type");
    focus_ring(ui, &response, response.rect, CORNER_RADIUS);
}

/// A flat button that reacts across all of `rect`, with a rounded highlight inset inside it.
///
/// Drawn by hand because the theme's minimum widget height (the field height) would otherwise
/// make a smaller `Button` overflow `rect` and shift its hover frame off-center.
pub fn icon_button(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    id_salt: &str,
    glyph: &str,
    font: egui::FontId,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let response = ui
        .interact(rect, ui.scope_id().with(id_salt), sense)
        .on_hover_text(label);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, label));

    let highlight = highlight_rect(rect);
    if enabled && (response.hovered() || response.has_focus()) {
        let fill = if response.is_pointer_button_down_on() {
            CONTROL_ACTIVE_COLOR
        } else {
            CONTROL_HOVER_COLOR
        };
        ui.painter().rect_filled(highlight, HIGHLIGHT_RADIUS, fill);
    }
    focus_ring(ui, &response, highlight, HIGHLIGHT_RADIUS);
    let color = if !enabled {
        DISABLED_ICON_COLOR
    } else if response.hovered() {
        TEXT_COLOR
    } else {
        MUTED_TEXT_COLOR
    };
    ui.painter().text(
        highlight.center(),
        egui::Align2::CENTER_CENTER,
        glyph,
        font,
        color,
    );
    response
}

/// A visible keyboard-focus indicator (WCAG 2.4.7) for widgets that have no outline of their own.
pub fn focus_ring(ui: &egui::Ui, response: &egui::Response, rect: egui::Rect, radius: u8) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect,
            radius,
            egui::Stroke::new(2.0, FOCUS_COLOR),
            egui::StrokeKind::Inside,
        );
    }
}

/// The hover highlight inside a control segment: inset evenly, but never narrower than tall.
fn highlight_rect(rect: egui::Rect) -> egui::Rect {
    let height = rect.height() - 2.0 * HIGHLIGHT_INSET;
    let width = (rect.width() - 2.0 * HIGHLIGHT_INSET).max(height.min(rect.width() - 8.0));
    egui::Rect::from_center_size(rect.center(), egui::vec2(width, height))
}

/// A `[−] n [+]` stepper for the password counter; the number can also be dragged or typed.
pub fn counter_stepper(ui: &mut egui::Ui, counter: &mut u32, width: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, FIELD_HEIGHT), egui::Sense::hover());
    ui.painter().rect_filled(rect, CORNER_RADIUS, CONTROL_COLOR);

    let minus_rect = rect.with_max_x(rect.left() + STEPPER_SEGMENT);
    let plus_rect = rect.with_min_x(rect.right() - STEPPER_SEGMENT);
    let value_rect = rect
        .with_min_x(minus_rect.right())
        .with_max_x(plus_rect.left());

    let minus = icon_button(
        ui,
        minus_rect,
        "counter_minus",
        "\u{2212}",
        egui::FontId::proportional(TEXT_SIZE),
        "Previous counter",
        *counter > 1,
    );
    if minus.clicked() {
        *counter = counter.saturating_sub(1).max(1);
    }
    ui.scope(|ui| {
        let counter_style = egui::TextStyle::Name("counter".into());
        let style = ui.style_mut();
        style
            .text_styles
            .insert(counter_style.clone(), egui::FontId::proportional(TEXT_SIZE));
        style.drag_value_text_style = counter_style;
        // Highlight the number like the buttons beside it: an inset pill, no outline.
        let value_highlight = value_rect.shrink2(egui::vec2(4.0, HIGHLIGHT_INSET));
        style.spacing.interact_size.y = value_highlight.height();
        let widgets = &mut style.visuals.widgets;
        widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
        widgets.inactive.bg_fill = Color32::TRANSPARENT;
        for state in [
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
        ] {
            state.corner_radius = HIGHLIGHT_RADIUS.into();
            state.bg_stroke = egui::Stroke::NONE;
            state.expansion = 0.0;
        }
        let value = ui
            .put(
                value_highlight,
                egui::DragValue::new(counter).range(1..=u32::MAX).speed(0.1),
            )
            .on_hover_text("Counter. Drag or type to change it.");
        focus_ring(ui, &value, value_highlight, HIGHLIGHT_RADIUS);
    });

    // Created after the number, so Tab visits the segments in the order they are drawn.
    let plus = icon_button(
        ui,
        plus_rect,
        "counter_plus",
        "+",
        egui::FontId::proportional(TEXT_SIZE),
        "Next counter",
        *counter < u32::MAX,
    );
    if plus.clicked() {
        *counter = counter.saturating_add(1);
    }

    // Dividers go on top so the hover fills of the segments don't cover them.
    let divider_y = egui::Rangef::new(rect.top() + 8.0, rect.bottom() - 8.0);
    let divider = egui::Stroke::new(1.0, DIVIDER_COLOR);
    ui.painter().vline(minus_rect.right(), divider_y, divider);
    ui.painter().vline(plus_rect.left(), divider_y, divider);
}
