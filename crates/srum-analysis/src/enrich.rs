use std::collections::HashMap;
use std::path::Path;
use anyhow::Result;
use serde::Serialize;

/// Classify a SID string into a well-known account type, or return `None`.
pub fn classify_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("system"),
        "S-1-5-19" => Some("local_service"),
        "S-1-5-20" => Some("network_service"),
        "S-1-1-0"  => Some("everyone"),
        _ if sid.starts_with("S-1-5-21-") && sid.ends_with("-500") => Some("local_admin"),
        _ if sid.starts_with("S-1-5-21-") => Some("domain_user"),
        _ => None,
    }
}

/// Split a Windows (or Unix) path into (directory, binary_name) at the last
/// path separator.  Returns `("", path)` when no separator is present.
pub fn split_windows_path(path: &str) -> (&str, &str) {
    match path.rfind(|c| c == '\\' || c == '/') {
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None => ("", path),
    }
}

/// Serialise a vec of records into a `Vec<serde_json::Value>`.
pub fn records_to_values<T: Serialize>(records: Vec<T>) -> Result<Vec<serde_json::Value>> {
    records
        .into_iter()
        .map(|r| serde_json::to_value(r).map_err(Into::into))
        .collect()
}

/// Build an id→name lookup from the id-map table in `path`.
///
/// Returns an empty map if the table cannot be read (non-fatal: resolution
/// is best-effort and the caller still outputs the raw integer IDs).
pub fn load_id_map(path: &Path) -> HashMap<i32, String> {
    srum_parser::parse_id_map(path)
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.id, e.name))
        .collect()
}

/// Inject `app_name` and `user_name` into a serialisable record.
///
/// Serialises `record` to a JSON object, then inserts resolved name fields
/// alongside the existing integer ID fields. Records whose IDs are absent
/// from `id_map` receive no extra field (not `null`).
pub fn enrich<T: Serialize>(record: T, id_map: &HashMap<i32, String>) -> serde_json::Value {
    let v = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    enrich_value(v, id_map)
}

/// Inject `app_name`, `user_name`, and `profile_name` into a connectivity record.
///
/// Same pattern as [`enrich`] but also resolves `profile_id` to `profile_name`.
pub fn enrich_connectivity(
    mut v: serde_json::Value,
    id_map: &HashMap<i32, String>,
) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        for &(id_key, name_key) in &[
            ("app_id", "app_name"),
            ("user_id", "user_name"),
            ("profile_id", "profile_name"),
        ] {
            if let Some(name) = obj
                .get(id_key)
                .and_then(serde_json::Value::as_i64)
                .and_then(|id| i32::try_from(id).ok())
                .and_then(|id| id_map.get(&id))
            {
                obj.insert(name_key.to_owned(), serde_json::Value::String(name.clone()));
            }
        }
    }
    v
}

/// Enrich a pre-serialised JSON value in-place with app_name / user_name / path signals.
pub fn enrich_value(mut v: serde_json::Value, id_map: &HashMap<i32, String>) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        if let Some(name) = obj
            .get("app_id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert("app_name".to_owned(), serde_json::Value::String(name.clone()));
            if name.contains('\\') || name.contains('/') {
                use forensicnomicon::heuristics::srum::{is_process_masquerade, is_suspicious_path};
                if is_suspicious_path(name) {
                    obj.insert("suspicious_path".to_owned(), serde_json::Value::Bool(true));
                }
                let (dir, bin) = split_windows_path(name);
                if is_process_masquerade(bin, dir) {
                    obj.insert("masquerade_candidate".to_owned(), serde_json::Value::Bool(true));
                }
            }
        }
        if let Some(name) = obj
            .get("user_id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert("user_name".to_owned(), serde_json::Value::String(name.clone()));
            if name.starts_with("S-") {
                if let Some(acct_type) = classify_sid(name) {
                    obj.insert("account_type".to_owned(), serde_json::Value::String(acct_type.to_owned()));
                }
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use serde_json::json;

    #[test]
    fn classify_sid_maps_system() {
        assert_eq!(classify_sid("S-1-5-18"), Some("system"));
    }

    #[test]
    fn classify_sid_returns_none_for_unknown() {
        assert_eq!(classify_sid("S-1-99-99"), None);
    }

    #[test]
    fn split_windows_path_splits_at_last_separator() {
        let (dir, bin) = split_windows_path(r"C:\Windows\System32\svchost.exe");
        assert_eq!(bin, "svchost.exe");
        assert!(dir.contains("System32"));
    }

    #[test]
    fn split_windows_path_no_separator_returns_empty_dir() {
        let (dir, bin) = split_windows_path("svchost.exe");
        assert_eq!(dir, "");
        assert_eq!(bin, "svchost.exe");
    }

    #[test]
    fn records_to_values_serialises_each_record() {
        #[derive(Serialize)]
        struct R { x: u32 }
        let records = vec![R { x: 1 }, R { x: 2 }];
        let values = records_to_values(records).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["x"], json!(1u32));
    }

    #[test]
    fn enrich_injects_app_name() {
        #[derive(Serialize)]
        struct R { app_id: i32 }
        let mut id_map = std::collections::HashMap::new();
        id_map.insert(42, "chrome.exe".to_owned());
        let v = enrich(R { app_id: 42 }, &id_map);
        assert_eq!(v["app_name"], json!("chrome.exe"));
    }

    #[test]
    fn enrich_injects_suspicious_path_flag() {
        #[derive(Serialize)]
        struct R { app_id: i32 }
        let mut id_map = std::collections::HashMap::new();
        id_map.insert(1, r"C:\Users\user\AppData\Local\Temp\malware.exe".to_owned());
        let v = enrich(R { app_id: 1 }, &id_map);
        assert_eq!(v["suspicious_path"], json!(true));
    }

    #[test]
    fn enrich_injects_account_type_for_known_sid() {
        #[derive(Serialize)]
        struct R { user_id: i32 }
        let mut id_map = std::collections::HashMap::new();
        id_map.insert(5, "S-1-5-18".to_owned());  // SYSTEM
        let v = enrich(R { user_id: 5 }, &id_map);
        assert_eq!(v["user_name"], json!("S-1-5-18"));
        assert_eq!(v["account_type"], json!("system"));
    }
}
