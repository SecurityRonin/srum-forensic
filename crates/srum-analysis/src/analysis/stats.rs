// TODO — implementation comes in GREEN commit

pub fn build_stats(_all: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    unimplemented!()
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
