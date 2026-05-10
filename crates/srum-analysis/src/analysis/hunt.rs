/// Plain enum — no Clap attributes. The CLI maps its own Clap-annotated enum to this.
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

/// Filter timeline records by partial app_id (integer) or app_name (case-insensitive substring).
pub fn filter_by_app(all: Vec<serde_json::Value>, query: &str) -> Vec<serde_json::Value> {
    let app_lower = query.to_lowercase();
    let app_id_filter: Option<i64> = query.parse().ok();
    all.into_iter()
        .filter(|v| {
            // match by integer app_id
            if let Some(id) = app_id_filter {
                if v.get("app_id").and_then(|x| x.as_i64()) == Some(id) {
                    return true;
                }
            }
            // match by app_name substring (case-insensitive)
            if let Some(name) = v.get("app_name").and_then(|x| x.as_str()) {
                if name.to_lowercase().contains(&app_lower) {
                    return true;
                }
            }
            false
        })
        .collect()
}

/// Filter timeline records matching a named forensic hunt signature.
pub fn hunt_filter(all: Vec<serde_json::Value>, sig: &HuntSignature) -> Vec<serde_json::Value> {
    let flag_key: Option<&str> = match sig {
        HuntSignature::Exfil          => Some("exfil_signal"),
        HuntSignature::Miner          => Some("background_cpu_dominant"),
        HuntSignature::Masquerade     => Some("masquerade_candidate"),
        HuntSignature::SuspiciousPath => Some("suspicious_path"),
        HuntSignature::NoFocus        => Some("no_focus_with_cpu"),
        HuntSignature::Phantom        => Some("phantom_foreground"),
        HuntSignature::Automated      => Some("automated_execution"),
        HuntSignature::Beaconing      => Some("beaconing"),
        HuntSignature::NotificationC2 => Some("notification_c2"),
        HuntSignature::All            => None,
    };

    all.into_iter()
        .filter(|v| match flag_key {
            Some(key) => v.get(key).and_then(|x| x.as_bool()) == Some(true),
            None => crate::pipeline::HEURISTIC_KEYS.iter().any(|&k| {
                v.get(k).and_then(|x| x.as_bool()) == Some(true)
            }),
        })
        .collect()
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
