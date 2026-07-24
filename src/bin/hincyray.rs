//! HincyRay router daemon binary.
//!
//! Thin entrypoint only. All logic lives in `xray_vpn_test::hincyray`
//! so the desktop app and the daemon share parser/probe/config code.

fn main() {
    if let Err(error) = xray_vpn_test::hincyray::run_cli() {
        eprintln!("hincyray: {error}");
        std::process::exit(1);
    }
}
