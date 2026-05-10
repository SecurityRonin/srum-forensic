// TODO — implementation in GREEN commit

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_timeline_returns_empty_for_nonexistent_path() {
        let result = build_timeline(std::path::Path::new("/nonexistent/SRUDB.dat"), None);
        assert!(result.is_empty());
    }

    #[test]
    fn table_key_is_source_table() {
        assert_eq!(TABLE_KEY, "source_table");
    }

    #[test]
    fn merge_focus_injects_into_apps_rows_only() {
        let mut all = vec![
            json!({"source_table": "apps", "app_id": 1_i64, "timestamp": "2024-01-01T00:00:00Z"}),
            json!({"source_table": "network", "app_id": 1_i64, "timestamp": "2024-01-01T00:00:00Z"}),
        ];
        let focus = vec![json!({
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "focus_time_ms": 60_000_u64,
            "user_input_time_ms": 1_000_u64,
        })];
        merge_focus_into_apps(&mut all, focus);
        assert_eq!(all[0]["focus_time_ms"], json!(60_000_u64));
        assert!(all[1].get("focus_time_ms").is_none(), "network row must not get focus data");
    }

    #[test]
    fn apply_heuristics_flags_background_cpu_dominant() {
        let mut values = vec![json!({
            "source_table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 100_000_u64,
        })];
        apply_heuristics(&mut values);
        assert_eq!(values[0]["background_cpu_dominant"], json!(true));
    }

    #[test]
    fn apply_heuristics_does_not_flag_with_wrong_key() {
        // Regression: old CLI used "table" key — ensure we don't accidentally accept it
        let mut values = vec![json!({
            "table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 0_u64,
        })];
        apply_heuristics(&mut values);
        assert!(values[0].get("background_cpu_dominant").is_none());
    }

    #[test]
    fn apply_heuristics_flags_automated_execution() {
        let mut values = vec![json!({
            "source_table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "focus_time_ms": 3_600_000_u64,
            "user_input_time_ms": 0_u64,
            "background_cycles": 1_u64,
            "foreground_cycles": 1_u64,
        })];
        apply_heuristics(&mut values);
        assert_eq!(values[0]["automated_execution"], json!(true));
    }

    #[test]
    fn annotate_user_presence_marks_timestamps_above_threshold() {
        let mut all = vec![
            json!({"source_table": "apps", "timestamp": "2024-01-01T00:00:00Z",
                   "user_input_time_ms": 15_000_u64}),
            json!({"source_table": "network", "timestamp": "2024-01-01T00:00:00Z"}),
        ];
        annotate_user_presence(&mut all);
        assert_eq!(all[0]["user_present"], json!(true));
        assert_eq!(all[1]["user_present"], json!(true));
    }
}
