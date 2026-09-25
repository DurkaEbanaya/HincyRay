//! Channel/preview availability only. This is not native video playback evidence.

use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::process::Command;
use std::sync::atomic::AtomicBool;

use serde_json::Value;
use tempfile::NamedTempFile;

use super::{ResourceTestResult, ensure_not_cancelled, run_cancellable_command};

pub const YOUTUBE_AVAILABILITY_CONTRACT_VERSION: u8 = 1;
const CHANNEL_URL: &str = "https://www.youtube.com/@MrBeast";
const CHANNEL_ID: &str = "UCX6OQ3DkcsbYNE6H8uQQuVA";
const PAGE_LIMIT: u64 = 2 * 1024 * 1024;
const IMAGE_LIMIT: u64 = 128 * 1024;
const PREVIEW_COUNT: usize = 3;
const IMAGE_MAX_DIMENSION: u32 = 1024;
const IMAGE_MAX_ALLOCATION: u64 = 16 * 1024 * 1024;

struct Capture {
    body: Vec<u8>,
    status: u16,
    mime: String,
    ttfb_ms: u32,
}

fn fetch_command(port: u16, url: &str, limit: u64, timeout: u64, file: &NamedTempFile) -> Command {
    let mut command = Command::new("curl");
    command
        .args([
            "-q",
            "--noproxy",
            "",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--socks5-hostname",
        ])
        .arg(format!("127.0.0.1:{port}"))
        .args(["--connect-timeout", "5", "--max-time"])
        .arg(timeout.to_string())
        .arg("--max-filesize")
        .arg(limit.to_string())
        .arg("--user-agent")
        .arg(super::YOUTUBE_PLAYER_USER_AGENT)
        .arg("--output")
        .arg(file.path())
        .args([
            "--write-out",
            "%{http_code}|%{content_type}|%{time_starttransfer}",
        ])
        .arg(url);
    command
}

fn fetch(
    port: u16,
    url: &str,
    limit: u64,
    timeout: u64,
    cancel: &AtomicBool,
) -> Result<Capture, (&'static str, bool)> {
    let file = NamedTempFile::new().map_err(|_| ("capture_setup", true))?;
    let output =
        run_cancellable_command(&mut fetch_command(port, url, limit, timeout, &file), cancel)
            .map_err(|_| ("command_unavailable", true))?;
    capture_response(output, &file, limit)
}

fn capture_response(
    output: std::process::Output,
    file: &NamedTempFile,
    limit: u64,
) -> Result<Capture, (&'static str, bool)> {
    let metrics = String::from_utf8_lossy(&output.stdout);
    let mut fields = metrics.trim().split('|');
    let status = fields
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|status| (200..600).contains(status));
    if !output.status.success() {
        // An HTTP refusal stays unknown even if transferring its body failed.
        if let Some(status) = status.filter(|status| *status >= 300) {
            return Ok(Capture {
                body: Vec::new(),
                status,
                mime: String::new(),
                ttfb_ms: 0,
            });
        }
        return Err(match output.status.code() {
            Some(5 | 6 | 7 | 28 | 35 | 52 | 55 | 56) => ("transport_error", false),
            Some(63) => ("body_limit", true),
            _ => ("fetch_error", true),
        });
    }
    let status = status.ok_or(("http_metrics", true))?;
    let mime = fields
        .next()
        .ok_or(("http_metrics", true))?
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let ttfb = fields
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or(("http_metrics", true))?;
    let mut body = Vec::new();
    file.reopen()
        .map_err(|_| ("capture_read", true))?
        .take(limit + 1)
        .read_to_end(&mut body)
        .map_err(|_| ("capture_read", true))?;
    if body.len() as u64 > limit {
        return Err(("body_limit", true));
    }
    Ok(Capture {
        body,
        status,
        mime,
        ttfb_ms: (ttfb * 1000.0) as u32,
    })
}

fn parse_channel(html: &[u8]) -> Result<Vec<String>, &'static str> {
    if html.len() as u64 > PAGE_LIMIT {
        return Err("page_body_limit");
    }
    let html = std::str::from_utf8(html).map_err(|_| "page_encoding")?;
    let initial = [
        "var ytInitialData = ",
        "ytInitialData = ",
        "window[\"ytInitialData\"] = ",
    ]
    .into_iter()
    .find_map(|marker| {
        let (_, tail) = html.split_once(marker)?;
        serde_json::Deserializer::from_str(tail)
            .into_iter::<Value>()
            .next()?
            .ok()
    })
    .ok_or("channel_data_missing")?;
    if initial["metadata"]["channelMetadataRenderer"]["externalId"] != CHANNEL_ID {
        return Err("channel_identity_not_confirmed");
    }
    let mut urls = Vec::new();
    thumbnails(&initial, &mut urls, &mut HashSet::new());
    if urls.len() != PREVIEW_COUNT {
        return Err("three_video_previews_missing");
    }
    Ok(urls)
}

fn thumbnails(value: &Value, urls: &mut Vec<String>, seen: &mut HashSet<String>) {
    if urls.len() >= PREVIEW_COUNT {
        return;
    }
    if let Some(object) = value.as_object() {
        if let Some(renderer) = object
            .get("videoRenderer")
            .or_else(|| object.get("gridVideoRenderer"))
            && let (Some(id), Some(list)) = (
                renderer["videoId"].as_str(),
                renderer["thumbnail"]["thumbnails"].as_array(),
            )
        {
            select_thumbnail(id, list, urls, seen);
        }
        if let Some(renderer) = object.get("lockupViewModel")
            && renderer["contentType"] == "LOCKUP_CONTENT_TYPE_VIDEO"
            && let (Some(id), Some(list)) = (
                renderer["contentId"].as_str(),
                renderer["contentImage"]["thumbnailViewModel"]["image"]["sources"].as_array(),
            )
        {
            select_thumbnail(id, list, urls, seen);
        }
        for child in object.values() {
            thumbnails(child, urls, seen);
        }
    } else if let Some(array) = value.as_array() {
        for child in array {
            thumbnails(child, urls, seen);
        }
    }
}

fn preview_url_allowed(id: &str, text: &str) -> bool {
    let Ok(url) = url::Url::parse(text) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("i.ytimg.com")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.fragment().is_none()
        && (url.path().starts_with(&format!("/vi/{id}/"))
            || url.path().starts_with(&format!("/vi_webp/{id}/")))
}

fn select_thumbnail(id: &str, list: &[Value], urls: &mut Vec<String>, seen: &mut HashSet<String>) {
    if urls.len() >= PREVIEW_COUNT
        || id.len() != 11
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || seen.contains(id)
    {
        return;
    }
    if let Some(text) = list
        .iter()
        .filter(|item| item["width"].as_u64().unwrap_or(0) >= 120)
        .filter_map(|item| item["url"].as_str())
        .find(|text| preview_url_allowed(id, text))
    {
        seen.insert(id.to_owned());
        urls.push(text.to_owned());
    }
}

fn image_valid(body: &[u8], mime: &str) -> bool {
    if body.len() as u64 > IMAGE_LIMIT {
        return false;
    }
    let format = match mime {
        "image/jpeg" => image::ImageFormat::Jpeg,
        "image/png" => image::ImageFormat::Png,
        "image/webp" => image::ImageFormat::WebP,
        _ => return false,
    };
    if image::guess_format(body).ok() != Some(format) {
        return false;
    }
    let complete = match format {
        image::ImageFormat::Jpeg => body.ends_with(&[0xff, 0xd9]),
        image::ImageFormat::Png => {
            body.ends_with(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82])
        }
        image::ImageFormat::WebP => body
            .get(4..8)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .is_some_and(|size| u64::from(u32::from_le_bytes(size)) + 8 == body.len() as u64),
        _ => false,
    };
    if !complete {
        return false;
    }
    let mut reader = image::ImageReader::new(Cursor::new(body));
    reader.set_format(format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(IMAGE_MAX_DIMENSION);
    limits.max_image_height = Some(IMAGE_MAX_DIMENSION);
    limits.max_alloc = Some(IMAGE_MAX_ALLOCATION);
    reader.limits(limits);
    reader
        .decode()
        .is_ok_and(|decoded| decoded.width() > 0 && decoded.height() > 0)
}

fn result(category: Option<&str>, reachable: bool, inconclusive: bool) -> ResourceTestResult {
    ResourceTestResult {
        contract_version: YOUTUBE_AVAILABILITY_CONTRACT_VERSION,
        id: "youtube_thumbnails".to_owned(),
        name: "YouTube channel and thumbnails".to_owned(),
        attempts: 1,
        successes: u32::from(category.is_none()),
        reachable,
        stable: category.is_none(),
        inconclusive,
        avg_ttfb_ms: 0,
        max_ttfb_ms: 0,
        avg_download_kbps: 0.0,
        error: category.map(|category| format!("YouTube availability: {category}")),
    }
}

pub(super) fn unavailable() -> ResourceTestResult {
    result(Some("proxy_setup_unavailable"), false, true)
}

pub(super) fn probe(port: u16, cancel: &AtomicBool) -> Result<ResourceTestResult, String> {
    probe_with_fetch(cancel, |url, limit, timeout| {
        fetch(port, url, limit, timeout, cancel)
    })
}

fn probe_with_fetch(
    cancel: &AtomicBool,
    mut fetch: impl FnMut(&str, u64, u64) -> Result<Capture, (&'static str, bool)>,
) -> Result<ResourceTestResult, String> {
    ensure_not_cancelled(cancel)?;
    let page = fetch(CHANNEL_URL, PAGE_LIMIT, 20);
    ensure_not_cancelled(cancel)?;
    let page = match page {
        Ok(page) => page,
        Err((category, unknown)) => return Ok(result(Some(category), false, unknown)),
    };
    if page.status != 200 {
        return Ok(result(Some("page_http_rejection"), true, true));
    }
    if page.mime != "text/html" {
        return Ok(result(Some("page_not_html"), true, true));
    }
    let urls = match parse_channel(&page.body) {
        Ok(urls) => urls,
        Err(category) => return Ok(result(Some(category), true, true)),
    };
    for url in urls {
        ensure_not_cancelled(cancel)?;
        let preview = fetch(&url, IMAGE_LIMIT, 8);
        ensure_not_cancelled(cancel)?;
        let preview = match preview {
            Ok(preview) => preview,
            Err((category, unknown)) => return Ok(result(Some(category), true, unknown)),
        };
        if preview.status != 200 {
            return Ok(result(Some("preview_http_rejection"), true, true));
        }
        if !image_valid(&preview.body, &preview.mime) {
            return Ok(result(Some("preview_decode_rejected"), true, true));
        }
    }
    ensure_not_cancelled(cancel)?;
    let mut passed = result(None, true, false);
    passed.avg_ttfb_ms = page.ttfb_ms;
    passed.max_ttfb_ms = page.ttfb_ms;
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::Ordering;

    fn channel_html() -> Vec<u8> {
        let videos = ["abcdefghijk", "ABCDEFGHIJK", "0123456789_"];
        let data = json!({
            "metadata": {"channelMetadataRenderer": {"externalId": CHANNEL_ID}},
            "contents": videos.into_iter().map(|id| json!({"videoRenderer": {
                "videoId": id,
                "thumbnail": {"thumbnails": [{"width": 320, "url": format!("https://i.ytimg.com/vi/{id}/mqdefault.jpg")} ]}
            }})).collect::<Vec<_>>()
        });
        format!("<html><script>var ytInitialData = {data};</script></html>").into_bytes()
    }

    fn encoded_image(width: u32, height: u32, format: image::ImageFormat) -> Vec<u8> {
        let mut bytes = Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(width, height)
            .write_to(&mut bytes, format)
            .expect("encode fixture");
        bytes.into_inner()
    }

    fn capture(body: Vec<u8>, status: u16, mime: &str) -> Capture {
        Capture {
            body,
            status,
            mime: mime.to_owned(),
            ttfb_ms: 12,
        }
    }

    #[test]
    fn parse_requires_known_channel_and_three_distinct_video_previews() {
        let html = channel_html();
        let urls = parse_channel(&html).expect("public channel with three videos");
        assert_eq!(urls.len(), PREVIEW_COUNT);
        let wrong_channel = String::from_utf8(html.clone())
            .expect("fixture utf8")
            .replace(CHANNEL_ID, "UCwrong");
        assert_eq!(
            parse_channel(wrong_channel.as_bytes()),
            Err("channel_identity_not_confirmed")
        );
        assert_eq!(
            parse_channel(b"<html>consent or login page</html>"),
            Err("channel_data_missing")
        );
        assert_eq!(
            parse_channel(b"var ytInitialData = {invalid}"),
            Err("channel_data_missing")
        );
        assert_eq!(parse_channel(&[0xff]), Err("page_encoding"));
        assert_eq!(
            parse_channel(&vec![b' '; PAGE_LIMIT as usize + 1]),
            Err("page_body_limit")
        );
        let duplicate = String::from_utf8(html)
            .expect("fixture utf8")
            .replace("ABCDEFGHIJK", "abcdefghijk");
        assert_eq!(
            parse_channel(duplicate.as_bytes()),
            Err("three_video_previews_missing")
        );
        for marker in ["ytInitialData = ", "window[\"ytInitialData\"] = "] {
            let html = String::from_utf8(channel_html())
                .expect("fixture utf8")
                .replace("var ytInitialData = ", marker);
            assert_eq!(
                parse_channel(html.as_bytes()).expect("supported assignment"),
                urls
            );
        }
    }

    #[test]
    fn filters_avatars_and_supports_grid_and_video_lockups_only() {
        let avatar = "https://yt3.googleusercontent.com/avatar";
        let mut data: Value = serde_json::from_str("{}").expect("empty object");
        data["metadata"] = json!({"channelMetadataRenderer": {"externalId": CHANNEL_ID}});
        data["contents"] = json!([
            {"channelRenderer": {"thumbnail": {"thumbnails": [{"width": 320, "url": avatar}]}}},
            {"videoRenderer": {"videoId": "abcdefghijk", "thumbnail": {"thumbnails": [{"width": 320, "url": avatar}]}}},
            {"lockupViewModel": {"contentId": "abcdefghijk", "contentType": "LOCKUP_CONTENT_TYPE_PLAYLIST", "contentImage": {"thumbnailViewModel": {"image": {"sources": [{"width": 320, "url": "https://i.ytimg.com/vi/abcdefghijk/mqdefault.jpg"}]}}}}}
        ]);
        let html = format!("var ytInitialData = {data};");
        assert_eq!(
            parse_channel(html.as_bytes()),
            Err("three_video_previews_missing")
        );
        data["contents"] = json!([
            {"gridVideoRenderer": {"videoId": "abcdefghijk", "thumbnail": {"thumbnails": [{"width": 320, "url": "https://i.ytimg.com/vi/abcdefghijk/mqdefault.jpg"}]}}},
            {"lockupViewModel": {"contentId": "ABCDEFGHIJK", "contentType": "LOCKUP_CONTENT_TYPE_VIDEO", "contentImage": {"thumbnailViewModel": {"image": {"sources": [{"width": 320, "url": "https://i.ytimg.com/vi_webp/ABCDEFGHIJK/mqdefault.webp"}]}}}}},
            {"videoRenderer": {"videoId": "0123456789_", "thumbnail": {"thumbnails": [{"width": 320, "url": "https://i.ytimg.com/vi/0123456789_/mqdefault.jpg"}]}}}
        ]);
        assert_eq!(
            parse_channel(format!("var ytInitialData = {data};").as_bytes())
                .expect("three renderer variants")
                .len(),
            3
        );
    }

    #[test]
    fn preview_hosts_paths_and_ports_are_pinned() {
        for url in [
            "https://i.ytimg.com/vi/abcdefghijk/mqdefault.jpg",
            "https://i.ytimg.com:443/vi_webp/abcdefghijk/mqdefault.webp?sqp=public",
        ] {
            assert!(preview_url_allowed("abcdefghijk", url));
        }
        for url in [
            "http://i.ytimg.com/vi/abcdefghijk/mqdefault.jpg",
            "https://i.ytimg.com:444/vi/abcdefghijk/mqdefault.jpg",
            "https://i.ytimg.com.evil.example/vi/abcdefghijk/mqdefault.jpg",
            "https://user:pass@i.ytimg.com/vi/abcdefghijk/mqdefault.jpg",
            "https://i.ytimg.com/avatar/abcdefghijk.jpg",
            "https://i.ytimg.com/vi/ABCDEFGHIJK/mqdefault.jpg",
            "https://i.ytimg.com/vi/abcdefghijk/../../avatar.jpg",
            "https://i.ytimg.com/vi/abcdefghijk/mqdefault.jpg#fragment",
            "https://127.0.0.1/vi/abcdefghijk/mqdefault.jpg",
        ] {
            assert!(!preview_url_allowed("abcdefghijk", url), "accepted {url}");
        }
    }

    #[test]
    fn images_require_actual_decode_and_bounded_dimensions() {
        assert_eq!(IMAGE_MAX_DIMENSION, 1024);
        assert_eq!(IMAGE_MAX_ALLOCATION, 16 * 1024 * 1024);
        for (format, mime) in [
            (image::ImageFormat::Jpeg, "image/jpeg"),
            (image::ImageFormat::Png, "image/png"),
            (image::ImageFormat::WebP, "image/webp"),
        ] {
            let bytes = encoded_image(320, 180, format);
            assert!(image_valid(&bytes, mime));
            assert!(!image_valid(&bytes, "text/html"));
            assert!(!image_valid(&bytes[..bytes.len() / 2], mime));
            assert!(!image_valid(&encoded_image(1025, 1, format), mime));
            assert!(!image_valid(&encoded_image(1, 1025, format), mime));
        }
        assert!(!image_valid(b"<html>not an image</html>", "image/jpeg"));
        assert!(!image_valid(&[0xff, 0xd8, 0xff, 0xd9], "image/jpeg"));
        assert!(!image_valid(
            &vec![0; IMAGE_LIMIT as usize + 1],
            "image/png"
        ));
        let png = encoded_image(1024, 1, image::ImageFormat::Png);
        assert!(image_valid(&png, "image/png"));
        assert!(!image_valid(&png, "image/jpeg"));
    }

    #[test]
    fn pass_requires_page_and_all_three_decoded_previews_not_video() {
        let mut calls = Vec::new();
        let image = encoded_image(320, 180, image::ImageFormat::Jpeg);
        let passed = probe_with_fetch(&AtomicBool::new(false), |url, limit, timeout| {
            calls.push(url.to_owned());
            Ok(if url == CHANNEL_URL {
                assert_eq!((limit, timeout), (PAGE_LIMIT, 20));
                capture(channel_html(), 200, "text/html")
            } else {
                assert_eq!((limit, timeout), (IMAGE_LIMIT, 8));
                capture(image.clone(), 200, "image/jpeg")
            })
        })
        .expect("availability probe");
        assert_eq!(calls.len(), 4);
        assert!(passed.stable && passed.reachable && !passed.inconclusive);
        assert_eq!(passed.successes, 1);
        assert_eq!(passed.contract_version, 1);
        assert_eq!(passed.id, "youtube_thumbnails");
        assert_eq!(passed.name, "YouTube channel and thumbnails");
        assert_eq!(passed.avg_download_kbps, 0.0);
        for failed_preview in 1..=3 {
            let mut call = 0;
            let failed = probe_with_fetch(&AtomicBool::new(false), |_, _, _| {
                call += 1;
                Ok(if call == 1 {
                    capture(channel_html(), 200, "text/html")
                } else if call == failed_preview + 1 {
                    capture(b"invalid JPEG".to_vec(), 200, "image/jpeg")
                } else {
                    capture(image.clone(), 200, "image/jpeg")
                })
            })
            .expect("invalid preview is unknown");
            assert!(!failed.stable && failed.reachable && failed.inconclusive);
            assert_eq!(failed.successes, 0);
        }
    }

    #[test]
    fn http_rejections_and_local_parse_are_unknown_not_pass() {
        for (status, mime, body) in [
            (429, "text/html", channel_html()),
            (302, "text/html", channel_html()),
            (200, "text/html", b"<html>login</html>".to_vec()),
            (200, "application/json", channel_html()),
        ] {
            let unknown = probe_with_fetch(&AtomicBool::new(false), |url, _, _| {
                assert_eq!(url, CHANNEL_URL);
                Ok(capture(body.clone(), status, mime))
            })
            .expect("unknown availability");
            assert!(unknown.inconclusive && unknown.reachable && !unknown.stable);
            assert_eq!(unknown.successes, 0);
            assert!(unknown.error.as_ref().expect("category").len() < 100);
        }
        for (category, unknown) in [("capture_setup", true), ("transport_error", false)] {
            let failed =
                probe_with_fetch(&AtomicBool::new(false), |_, _, _| Err((category, unknown)))
                    .expect("classified error");
            assert!(!failed.stable && !failed.reachable);
            assert_eq!(failed.inconclusive, unknown);
        }
    }

    #[test]
    fn cancellation_prevents_or_interrupts_fetch() {
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            probe_with_fetch(&cancelled, |_, _, _| panic!("must not fetch")).expect_err("cancel"),
            "benchmark cancelled"
        );
        assert_eq!(
            probe(1, &cancelled).expect_err("probe cancellation"),
            "benchmark cancelled"
        );
        let cancel = AtomicBool::new(false);
        assert_eq!(
            probe_with_fetch(&cancel, |_, _, _| {
                cancel.store(true, Ordering::Relaxed);
                Err(("command_unavailable", true))
            })
            .expect_err("interrupted fetch"),
            "benchmark cancelled"
        );
    }

    #[test]
    fn thumbnail_workers_do_not_wait_for_native_youtube_probe_lock() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test port");
        let port = socket.local_addr().expect("local test address").port();
        drop(socket);
        let native_guard = super::super::youtube_probe_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let cancel = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(Barrier::new(5));
        let (sender, receiver) = mpsc::channel();
        let workers = (0..4)
            .map(|_| {
                let cancel = Arc::clone(&cancel);
                let ready = Arc::clone(&ready);
                let sender = sender.clone();
                std::thread::spawn(move || {
                    ready.wait();
                    let _ = sender.send(probe(port, &cancel));
                })
            })
            .collect::<Vec<_>>();
        ready.wait();
        // A closed local SOCKS port prevents external requests. Each worker must
        // finish its own fetch without waiting for the held native playback lock.
        let completed = (0..4).all(|_| receiver.recv_timeout(Duration::from_secs(3)).is_ok());
        cancel.store(true, Ordering::Relaxed);
        drop(native_guard);
        for worker in workers {
            worker.join().expect("thumbnail worker exits");
        }
        assert!(
            completed,
            "thumbnail workers waited for the native playback lock"
        );
    }

    #[test]
    fn curl_disables_config_and_proxy_bypass_without_redirects_or_cookies() {
        let file = NamedTempFile::new().expect("private capture");
        let command = fetch_command(12345, CHANNEL_URL, PAGE_LIMIT, 20, &file);
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "-q");
        for pair in [
            ["--noproxy", ""],
            ["--proto", "=https"],
            ["--socks5-hostname", "127.0.0.1:12345"],
            ["--connect-timeout", "5"],
            ["--max-time", "20"],
            ["--max-filesize", "2097152"],
        ] {
            assert!(
                args.windows(2)
                    .any(|args| args[0] == pair[0] && args[1] == pair[1])
            );
        }
        assert!(!args.iter().any(|arg| matches!(
            arg.as_str(),
            "-L" | "--location" | "--cookie" | "--cookie-jar"
        )));
        assert_eq!(args.last().map(String::as_str), Some(CHANNEL_URL));
    }

    #[cfg(unix)]
    #[test]
    fn http_refusal_survives_failed_transfer_and_errors_never_include_stderr() {
        use std::os::unix::process::ExitStatusExt;
        let file = NamedTempFile::new().expect("private capture");
        let output = |rc, http| std::process::Output {
            status: std::process::ExitStatus::from_raw(rc << 8),
            stdout: format!("{http}|text/html|0.1").into_bytes(),
            stderr: b"untrusted body and https://provider.example/sub/<token>".to_vec(),
        };
        for rc in [28, 35, 56, 63] {
            let capture = capture_response(output(rc, "429"), &file, PAGE_LIMIT)
                .expect("HTTP refusal retained");
            assert_eq!(capture.status, 429);
            let unknown = probe_with_fetch(&AtomicBool::new(false), |_, _, _| {
                capture_response(output(rc, "429"), &file, PAGE_LIMIT)
            })
            .expect("refusal is unknown");
            assert!(unknown.reachable && unknown.inconclusive && !unknown.stable);
            assert_eq!(
                unknown.error.as_deref(),
                Some("YouTube availability: page_http_rejection")
            );
        }
        for (rc, expected) in [
            (28, ("transport_error", false)),
            (23, ("fetch_error", true)),
            (63, ("body_limit", true)),
        ] {
            assert_eq!(
                capture_response(output(rc, "000"), &file, PAGE_LIMIT).err(),
                Some(expected)
            );
        }
    }
}
