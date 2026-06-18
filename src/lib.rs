// Shared modules: available in every build, including the lightweight
// `hincyray` router daemon built with `--no-default-features`.
pub mod hincyray;
pub mod profiles;
pub mod scoring;
pub mod tester;
pub mod xray_config;

// Desktop GUI surface: only compiled when the `desktop` feature is on.
// Keeps eframe/egui/arboard out of the Entware/OpenWrt daemon build.
#[cfg(feature = "desktop")]
pub mod app;
#[cfg(feature = "desktop")]
pub mod theme;

#[cfg(feature = "desktop")]
pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("XrayVpnTest")
            .with_inner_size([1660.0, 860.0])
            .with_min_inner_size([1280.0, 680.0]),
        ..Default::default()
    };

    eframe::run_native(
        "XrayVpnTest",
        options,
        Box::new(|cc| Ok(Box::new(app::XrayVpnTestApp::new(cc)))),
    )
}
