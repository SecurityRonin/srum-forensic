// TODO — implementation comes in GREEN commit

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
