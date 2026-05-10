// TODO: implementation

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
}
