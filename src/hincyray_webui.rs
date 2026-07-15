//! Embedded WebUI boundary.
//!
//! HTTP routing depends on this module rather than knowing filesystem layout.
//! This keeps future asset/module migration out of the daemon core.

pub fn index_html() -> &'static str {
    include_str!("webui/index.html")
}
