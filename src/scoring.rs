//! Shared quality-score computation.
//!
//! Used by both the desktop benchmark harness (`tester.rs`) and the
//! HincyRay router daemon so both surfaces agree on what "best server"
//! means. Keeping the formula in one place prevents drift between the
//! macOS diagnostics UI and the Keenetic client.

/// Quality score in `0..=100` from raw benchmark metrics.
///
/// Composite of short download speed (weight 70), latency penalty
/// (capped at 30), jitter penalty (capped at 20), and packet-loss
/// penalty (capped at 35). The base constant is 45.
#[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn quality_score(
    latency_ms: u32,
    jitter_ms: u32,
    download_mbps: f32,
    loss_percent: f32,
) -> u32 {
    let speed_score = (download_mbps.min(200.0) / 200.0) * 70.0;
    let latency_penalty = (latency_ms as f32 / 8.0).min(30.0);
    let jitter_penalty = (jitter_ms as f32 / 2.5).min(20.0);
    let loss_penalty = (loss_percent * 12.0).min(35.0);
    (speed_score + 45.0 - latency_penalty - jitter_penalty - loss_penalty)
        .clamp(0.0, 100.0)
        .round() as u32
}

#[cfg(test)]
mod tests {
    use super::quality_score;

    #[test]
    fn perfect_metrics_hit_ceiling() {
        let score = quality_score(20, 1, 200.0, 0.0);
        assert_eq!(score, 100);
    }

    #[test]
    fn terrible_metrics_floor_at_zero() {
        let score = quality_score(2000, 200, 0.0, 100.0);
        assert_eq!(score, 0);
    }

    #[test]
    fn moderate_metrics_land_in_middle_band() {
        let score = quality_score(120, 30, 50.0, 0.0);
        assert!(
            (30..80).contains(&score),
            "expected mid-band score, got {score}"
        );
    }

    #[test]
    fn loss_only_still_scores_when_speed_is_high() {
        let score = quality_score(40, 2, 150.0, 1.0);
        assert!(
            score >= 80,
            "expected high score with mild loss, got {score}"
        );
    }
}
