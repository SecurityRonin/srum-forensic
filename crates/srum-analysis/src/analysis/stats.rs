use std::collections::{HashMap, HashSet};

/// Aggregate per-process statistics from a merged timeline.
///
/// Returns a `Vec` sorted by `flag_count` descending, then
/// `total_background_cycles` descending.
pub fn build_stats(all: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    struct AppStats {
        app_id: i64,
        app_name: Option<String>,
        bg_cycles: u64,
        fg_cycles: u64,
        bytes_sent: u64,
        bytes_recv: u64,
        count: u64,
        first_seen: Option<String>,
        last_seen: Option<String>,
        flags: HashSet<String>,
    }

    let mut map: HashMap<i64, AppStats> = HashMap::new();

    for v in &all {
        if let Some(app_id) = v.get("app_id").and_then(|x| x.as_i64()) {
            let entry = map.entry(app_id).or_insert(AppStats {
                app_id,
                app_name: None,
                bg_cycles: 0,
                fg_cycles: 0,
                bytes_sent: 0,
                bytes_recv: 0,
                count: 0,
                first_seen: None,
                last_seen: None,
                flags: HashSet::new(),
            });
            entry.count += 1;
            // app_name (first resolved name wins)
            if entry.app_name.is_none() {
                entry.app_name = v.get("app_name").and_then(|x| x.as_str()).map(str::to_owned);
            }
            // cycles
            entry.bg_cycles += v.get("background_cycles").and_then(|x| x.as_u64()).unwrap_or(0);
            entry.fg_cycles += v.get("foreground_cycles").and_then(|x| x.as_u64()).unwrap_or(0);
            // bytes
            entry.bytes_sent += v.get("bytes_sent").and_then(|x| x.as_u64()).unwrap_or(0);
            entry.bytes_recv += v
                .get("bytes_received")
                .and_then(|x| x.as_u64())
                .or_else(|| v.get("bytes_recv").and_then(|x| x.as_u64()))
                .unwrap_or(0);
            // timestamps
            if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
                let ts = ts.to_owned();
                if entry.first_seen.as_deref().map_or(true, |f: &str| ts.as_str() < f) {
                    entry.first_seen = Some(ts.clone());
                }
                if entry.last_seen.as_deref().map_or(true, |l: &str| ts.as_str() > l) {
                    entry.last_seen = Some(ts);
                }
            }
            // heuristic flags (boolean true only)
            for &key in crate::pipeline::HEURISTIC_KEYS {
                if v.get(key).and_then(|x| x.as_bool()) == Some(true) {
                    entry.flags.insert(key.to_owned());
                }
            }
        }
    }

    let mut stats: Vec<serde_json::Value> = map
        .into_values()
        .map(|s| {
            let mut flags: Vec<String> = s.flags.into_iter().collect();
            flags.sort();
            let flag_count = flags.len() as u64;
            let mut obj = serde_json::json!({
                "app_id": s.app_id,
                "total_background_cycles": s.bg_cycles,
                "total_foreground_cycles": s.fg_cycles,
                "total_bytes_sent": s.bytes_sent,
                "total_bytes_received": s.bytes_recv,
                "active_intervals": s.count,
                "heuristic_flags": flags,
                "flag_count": flag_count,
            });
            if let (Some(f), Some(l)) = (s.first_seen, s.last_seen) {
                obj.as_object_mut()
                    .unwrap()
                    .insert("first_seen".into(), f.into());
                obj.as_object_mut()
                    .unwrap()
                    .insert("last_seen".into(), l.into());
            }
            if let Some(name) = s.app_name {
                obj.as_object_mut()
                    .unwrap()
                    .insert("app_name".into(), name.into());
            }
            obj
        })
        .collect();

    // Sort: flag_count desc, then total_background_cycles desc
    stats.sort_by(|a, b| {
        let fa = a.get("flag_count").and_then(|x| x.as_u64()).unwrap_or(0);
        let fb = b.get("flag_count").and_then(|x| x.as_u64()).unwrap_or(0);
        fb.cmp(&fa).then_with(|| {
            let ba = a
                .get("total_background_cycles")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let bb = b
                .get("total_background_cycles")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            bb.cmp(&ba)
        })
    });

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_stats_empty_returns_empty() {
        assert!(build_stats(vec![]).is_empty());
    }

    #[test]
    fn build_stats_aggregates_by_app_id() {
        let records = vec![
            json!({"app_id": 1_i64, "background_cycles": 100_u64, "source_table": "apps"}),
            json!({"app_id": 1_i64, "background_cycles": 200_u64, "source_table": "apps"}),
        ];
        let stats = build_stats(records);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0]["total_background_cycles"], json!(300_u64));
    }
}
