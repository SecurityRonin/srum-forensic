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
