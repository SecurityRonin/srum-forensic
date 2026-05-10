// TODO — implementation comes in GREEN commit

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_sessions_empty_timeline_returns_empty() {
        assert!(build_sessions(&[]).is_empty());
    }

    #[test]
    fn build_sessions_no_user_present_returns_empty() {
        let all = vec![json!({"source_table": "apps", "timestamp": "2024-01-01T00:00:00Z"})];
        assert!(build_sessions(&all).is_empty());
    }
}
