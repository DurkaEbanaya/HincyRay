use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};

pub fn apply(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = fluent_dark_visuals();
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(0);
    style.text_styles = [
        (
            TextStyle::Heading,
            FontId::new(26.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        ),
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
    ]
    .into();
    ctx.set_style(style);
}

fn fluent_dark_visuals() -> Visuals {
    let mut visuals = Visuals::dark();
    visuals.window_fill = Color32::from_rgb(16, 16, 16);
    visuals.panel_fill = Color32::from_rgb(20, 22, 25);
    visuals.faint_bg_color = Color32::from_rgba_unmultiplied(255, 255, 255, 10);
    visuals.extreme_bg_color = Color32::from_rgb(12, 14, 17);
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(25, 28, 33);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(43, 43, 43);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(55, 63, 73);
    visuals.widgets.active.bg_fill = Color32::from_rgb(0, 120, 215);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(73, 73, 73));
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(96, 158, 210));
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0, 120, 215));
    visuals.widgets.inactive.corner_radius = CornerRadius::same(2);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(2);
    visuals.widgets.active.corner_radius = CornerRadius::same(2);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(242, 242, 242));
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.hyperlink_color = Color32::from_rgb(77, 166, 255);
    visuals.selection.bg_fill = Color32::from_rgb(0, 120, 215);
    visuals.window_corner_radius = CornerRadius::same(0);
    visuals
}
