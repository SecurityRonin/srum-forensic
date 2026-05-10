use crate::pipeline::TABLE_KEY;

/// Build user sessions from a merged SRUM timeline.
///
/// A session is a continuous span of `user_present == true` timestamps with
/// gaps of ≤ 2 hours between consecutive entries. Returns an empty Vec if
/// no user-present records exist.
pub fn build_sessions(all: &[serde_json::Value]) -> Vec<serde_json::Value> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut present_ts: BTreeSet<String> = BTreeSet::new();
    let mut input_by_ts: BTreeMap<String, u64> = BTreeMap::new();

    for v in all {
        if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
            if v.get("user_present").and_then(|x| x.as_bool()) == Some(true) {
                present_ts.insert(ts.to_owned());
            }
            if v.get(TABLE_KEY).and_then(|x| x.as_str()) == Some("apps") {
                if let Some(ms) = v.get("user_input_time_ms").and_then(|x| x.as_u64()) {
                    *input_by_ts.entry(ts.to_owned()).or_insert(0) += ms;
                }
            }
        }
    }

    if present_ts.is_empty() {
        return vec![];
    }

    const SESSION_GAP_SECS: i64 = 7_200; // 2 hours

    let mut sessions: Vec<serde_json::Value> = Vec::new();
    let mut iter = present_ts.iter();
    let first = iter.next().unwrap();
    let mut session_start = first.clone();
    let mut session_end = first.clone();
    let mut session_input: u64 = input_by_ts.get(first).copied().unwrap_or(0);

    for ts in iter {
        let gap = super::iso_diff_secs(&session_end, ts);
        if gap > SESSION_GAP_SECS {
            sessions.push(make_session(&session_start, &session_end, session_input));
            session_start = ts.clone();
            session_input = 0;
        }
        session_end = ts.clone();
        session_input += input_by_ts.get(ts).copied().unwrap_or(0);
    }
    sessions.push(make_session(&session_start, &session_end, session_input));
    sessions
}

fn make_session(start: &str, end: &str, input_ms: u64) -> serde_json::Value {
    let duration_secs = super::iso_diff_secs(start, end).max(0);
    let duration_hours = (duration_secs as f64 / 3600.0).ceil() as u64;
    serde_json::json!({
        "session_start": start,
        "session_end": end,
        "duration_hours": duration_hours,
        "input_ms_total": input_ms,
    })
}

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
        let all = vec![json!({"source_table": "apps", "timestamp": "2024-01-01T00:00:00Z", "user_present": false})];
        assert!(build_sessions(&all).is_empty());
    }
}
