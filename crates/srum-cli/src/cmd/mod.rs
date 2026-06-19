pub mod analysis;
pub mod forensics;
pub mod tables;

use std::collections::HashMap;
use std::path::Path;

/// Emitted (once) when name resolution was requested but `SruDbIdMapTable` is
/// empty or unreadable while there is still output to produce, so the analyst
/// knows the raw IDs in the result were *not* enriched (degrade-to-raw, not a
/// silent empty result).
const RESOLVE_DEGRADE_WARNING: &str =
    "warning: could not resolve names from SruDbIdMapTable; emitting raw IDs";

/// The degradation condition: resolution produced an empty map while there is
/// still output to emit. Pure so it can be unit-tested; `eprintln!` side-effects
/// stay at the call sites.
fn is_resolution_degraded(map_empty: bool, have_output: bool) -> bool {
    have_output && map_empty
}

/// Load the `app_id`/`user_id` → name map, warning to stderr when resolution
/// was asked for but degraded to raw IDs.
///
/// `have_output` says whether the caller still has records to emit; the warning
/// is suppressed for a genuinely empty result (a clean DB with nothing to
/// resolve is not a degradation).
pub fn load_id_map_or_warn(path: &Path, have_output: bool) -> HashMap<i32, String> {
    let id_map = srum_analysis::load_id_map(path);
    if is_resolution_degraded(id_map.is_empty(), have_output) {
        eprintln!("{RESOLVE_DEGRADE_WARNING}");
    }
    id_map
}

/// Warn (once) when resolution was requested (`id_map` is `Some`) but the map is
/// empty while there is still output to emit. For timeline-style handlers where
/// the map is consumed by `build_timeline` before output size is known.
pub fn warn_if_resolution_degraded(id_map: Option<&HashMap<i32, String>>, have_output: bool) {
    if let Some(map) = id_map {
        if is_resolution_degraded(map.is_empty(), have_output) {
            eprintln!("{RESOLVE_DEGRADE_WARNING}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degraded_when_empty_map_and_output_present() {
        assert!(is_resolution_degraded(true, true));
    }

    #[test]
    fn not_degraded_when_output_empty() {
        // A genuinely empty result is not a degradation, even with an empty map.
        assert!(!is_resolution_degraded(true, false));
    }

    #[test]
    fn not_degraded_when_map_populated() {
        assert!(!is_resolution_degraded(false, true));
        assert!(!is_resolution_degraded(false, false));
    }

    #[test]
    fn warn_helper_skips_when_resolution_not_requested() {
        // id_map None (no --resolve) must never warn, regardless of output.
        warn_if_resolution_degraded(None, true);
    }
}
