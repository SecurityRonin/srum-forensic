use std::collections::HashMap;

/// Compare two collections of per-process stats (produced by `build_stats`).
///
/// Returns a JSON object with three keys:
/// - `new_processes`       — in suspect but not baseline
/// - `departed_processes`  — in baseline but not suspect
/// - `changed`             — in both, with new heuristic flags or non-zero byte/cycle deltas
pub fn compare_databases(
    baseline_stats: Vec<serde_json::Value>,
    suspect_stats: Vec<serde_json::Value>,
) -> serde_json::Value {
    // Key each stat by app_name if present, else app_id string.
    fn process_key(v: &serde_json::Value) -> String {
        v.get("app_name")
            .and_then(|x| x.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                v.get("app_id")
                    .and_then(|x| x.as_i64())
                    .map(|id| id.to_string())
                    .unwrap_or_default()
            })
    }

    let baseline_map: HashMap<String, &serde_json::Value> =
        baseline_stats.iter().map(|v| (process_key(v), v)).collect();
    let suspect_map: HashMap<String, &serde_json::Value> =
        suspect_stats.iter().map(|v| (process_key(v), v)).collect();

    let mut new_processes: Vec<serde_json::Value> = Vec::new();
    let mut departed_processes: Vec<serde_json::Value> = Vec::new();
    let mut changed: Vec<serde_json::Value> = Vec::new();

    // New: in suspect but not in baseline.
    for (key, sv) in &suspect_map {
        if !baseline_map.contains_key(key) {
            new_processes.push((*sv).clone());
        }
    }

    // Departed: in baseline but not in suspect.
    for (key, bv) in &baseline_map {
        if !suspect_map.contains_key(key) {
            let mut entry = serde_json::json!({});
            if let Some(id) = bv.get("app_id") {
                entry.as_object_mut().unwrap().insert("app_id".into(), id.clone());
            }
            if let Some(name) = bv.get("app_name") {
                entry.as_object_mut().unwrap().insert("app_name".into(), name.clone());
            }
            departed_processes.push(entry);
        }
    }

    // Changed: in both, with new flags or significant deltas.
    for (key, sv) in &suspect_map {
        if let Some(bv) = baseline_map.get(key) {
            let b_flags: Vec<String> = bv
                .get("heuristic_flags")
                .and_then(|f| f.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default();
            let s_flags: Vec<String> = sv
                .get("heuristic_flags")
                .and_then(|f| f.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default();

            let new_flags: Vec<&str> = s_flags
                .iter()
                .filter(|f| !b_flags.contains(f))
                .map(String::as_str)
                .collect();

            let b_bytes = bv.get("total_bytes_sent").and_then(|x| x.as_i64()).unwrap_or(0);
            let s_bytes = sv.get("total_bytes_sent").and_then(|x| x.as_i64()).unwrap_or(0);
            let delta_bytes = s_bytes - b_bytes;

            let b_bg = bv.get("total_background_cycles").and_then(|x| x.as_i64()).unwrap_or(0);
            let s_bg = sv.get("total_background_cycles").and_then(|x| x.as_i64()).unwrap_or(0);
            let delta_bg = s_bg - b_bg;

            if !new_flags.is_empty() || delta_bytes != 0 || delta_bg != 0 {
                let mut entry = serde_json::json!({
                    "new_flags": new_flags,
                    "delta_bytes_sent": delta_bytes,
                    "delta_background_cycles": delta_bg,
                });
                if let Some(id) = sv.get("app_id") {
                    entry.as_object_mut().unwrap().insert("app_id".into(), id.clone());
                }
                if let Some(name) = sv.get("app_name") {
                    entry.as_object_mut().unwrap().insert("app_name".into(), name.clone());
                }
                changed.push(entry);
            }
        }
    }

    // Sort each section by app_id for deterministic output.
    let sort_by_id = |a: &serde_json::Value, b: &serde_json::Value| {
        let ia = a.get("app_id").and_then(|x| x.as_i64()).unwrap_or(0);
        let ib = b.get("app_id").and_then(|x| x.as_i64()).unwrap_or(0);
        ia.cmp(&ib)
    };
    new_processes.sort_by(sort_by_id);
    departed_processes.sort_by(sort_by_id);
    changed.sort_by(sort_by_id);

    serde_json::json!({
        "new_processes": new_processes,
        "departed_processes": departed_processes,
        "changed": changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compare_databases_empty_both_returns_empty_diff() {
        let result = compare_databases(vec![], vec![]);
        assert!(result["new_processes"].as_array().unwrap().is_empty());
        assert!(result["departed_processes"].as_array().unwrap().is_empty());
        assert!(result["changed"].as_array().unwrap().is_empty());
    }

    #[test]
    fn compare_databases_new_process_detected() {
        let baseline = vec![];
        let suspect = vec![json!({"app_id": 99_i64, "app_name": "evil.exe"})];
        let result = compare_databases(baseline, suspect);
        assert_eq!(result["new_processes"].as_array().unwrap().len(), 1);
    }
}
