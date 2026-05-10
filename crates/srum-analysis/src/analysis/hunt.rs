// TODO — implementation comes in GREEN commit

#[derive(Debug, Clone, PartialEq)]
pub enum HuntSignature {
    Exfil,
    Miner,
    Masquerade,
    SuspiciousPath,
    NoFocus,
    Phantom,
    Automated,
    Beaconing,
    NotificationC2,
    All,
}

pub fn filter_by_app(_all: Vec<serde_json::Value>, _query: &str) -> Vec<serde_json::Value> {
    unimplemented!()
}

pub fn hunt_filter(_all: Vec<serde_json::Value>, _sig: &HuntSignature) -> Vec<serde_json::Value> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn filter_by_app_matches_by_id() {
        let all = vec![
            json!({"app_id": 42_i64}),
            json!({"app_id": 99_i64}),
        ];
        let filtered = filter_by_app(all, "42");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["app_id"], json!(42_i64));
    }

    #[test]
    fn hunt_filter_automated_returns_only_flagged() {
        let all = vec![
            json!({"automated_execution": true}),
            json!({"suspicious_path": true}),
        ];
        let filtered = hunt_filter(all, &HuntSignature::Automated);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["automated_execution"], json!(true));
    }
}
