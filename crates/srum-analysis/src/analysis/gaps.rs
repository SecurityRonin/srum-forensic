use crate::pipeline::TABLE_KEY;

/// Detect temporal gaps in a merged SRUM timeline.
///
/// Returns gap objects sorted by `start`. Two gap types:
/// - `system_off`: all tables share the gap window.
/// - `selective_gap`: only some tables have the gap while others have records.
pub fn detect_gaps(all: &[serde_json::Value], threshold_hours: u64) -> Vec<serde_json::Value> {
    use std::collections::{BTreeSet, HashMap};

    let threshold_secs = (threshold_hours * 3600) as i64;

    // Collect timestamps per source_table
    let mut by_table: HashMap<String, BTreeSet<String>> = HashMap::new();
    for v in all {
        if let (Some(table), Some(ts)) = (
            v.get(TABLE_KEY).and_then(|x| x.as_str()),
            v.get("timestamp").and_then(|x| x.as_str()),
        ) {
            by_table
                .entry(table.to_owned())
                .or_default()
                .insert(ts.to_owned());
        }
    }

    if by_table.is_empty() {
        return vec![];
    }

    struct Gap {
        table: String,
        start: String,
        end: String,
    }
    let mut all_gaps: Vec<Gap> = Vec::new();

    for (table, timestamps) in &by_table {
        let ts_vec: Vec<&String> = timestamps.iter().collect();
        for w in ts_vec.windows(2) {
            let diff = super::iso_diff_secs(w[0], w[1]);
            if diff >= threshold_secs {
                all_gaps.push(Gap {
                    table: table.clone(),
                    start: w[0].clone(),
                    end: w[1].clone(),
                });
            }
        }
    }

    let tables: Vec<String> = by_table.keys().cloned().collect();

    // Group gaps by (start, end) to determine system_off vs selective
    let mut gap_map: HashMap<(String, String), Vec<String>> = HashMap::new();
    for g in all_gaps {
        gap_map
            .entry((g.start, g.end))
            .or_default()
            .push(g.table);
    }

    let mut result: Vec<serde_json::Value> = Vec::new();

    for ((start, end), affected_tables) in &gap_map {
        let gap_secs = super::iso_diff_secs(start, end).max(0);
        let gap_hours = gap_secs / 3600;
        if affected_tables.len() == tables.len() {
            let mut at = affected_tables.clone();
            at.sort();
            result.push(serde_json::json!({
                "type": "system_off",
                "start": start,
                "end": end,
                "gap_hours": gap_hours,
                "tables_affected": at,
            }));
        } else {
            for t in affected_tables {
                result.push(serde_json::json!({
                    "type": "selective_gap",
                    "start": start,
                    "end": end,
                    "gap_hours": gap_hours,
                    "source_table": t,
                    "other_tables_active": true,
                }));
            }
        }
    }

    // Sort by start timestamp
    result.sort_by(|a, b| {
        let sa = a.get("start").and_then(|v| v.as_str()).unwrap_or("");
        let sb = b.get("start").and_then(|v| v.as_str()).unwrap_or("");
        sa.cmp(sb)
    });

    result
}

/// Detect auto-increment gaps in a list of record IDs for the given table.
///
/// A gap means rows were deleted. Returns one object per gap range with
/// `gap_start`, `gap_end`, `deleted_count`, and `autoinc_gap: true`.
pub fn detect_autoinc_gaps_from_ids(table: &str, ids: &[u32]) -> Vec<serde_json::Value> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    let mut gaps = Vec::new();
    for w in sorted.windows(2) {
        if w[1] > w[0] + 1 {
            let gap_start = w[0] + 1;
            let gap_end = w[1] - 1;
            let deleted_count = u64::from(gap_end - gap_start + 1);
            gaps.push(serde_json::json!({
                "source_table": table,
                "gap_start": gap_start,
                "gap_end": gap_end,
                "deleted_count": deleted_count,
                "autoinc_gap": true,
            }));
        }
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detect_autoinc_gaps_finds_deleted_range() {
        let ids = vec![1u32, 2, 5, 6]; // gap at 3-4
        let gaps = detect_autoinc_gaps_from_ids("apps", &ids);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["gap_start"], json!(3u32));
        assert_eq!(gaps[0]["gap_end"], json!(4u32));
        assert_eq!(gaps[0]["deleted_count"], json!(2u64));
    }

    #[test]
    fn detect_autoinc_gaps_empty_on_contiguous_ids() {
        let ids = vec![1u32, 2, 3, 4];
        assert!(detect_autoinc_gaps_from_ids("apps", &ids).is_empty());
    }

    #[test]
    fn detect_gaps_empty_timeline_returns_empty() {
        assert!(detect_gaps(&[], 2).is_empty());
    }
}
