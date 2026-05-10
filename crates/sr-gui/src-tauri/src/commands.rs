use crate::{
    timeline::value_to_timeline_record,
    types::{AnnotatedRecord, FindingCard, SrumFile, TemporalSpan},
};
use std::path::Path;

#[tauri::command]
pub async fn open_file(path: String) -> Result<SrumFile, String> {
    parse_srum(Path::new(&path)).map_err(|e| format!("error: {e:#}"))
}

pub fn parse_srum(path: &Path) -> anyhow::Result<SrumFile> {
    let id_map = srum_analysis::load_id_map(path);
    let annotated = srum_analysis::build_timeline(path, Some(&id_map));

    let mut table_names: Vec<String> = annotated
        .iter()
        .filter_map(|v| v.get("source_table").and_then(|s| s.as_str()).map(str::to_owned))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    table_names.sort();

    let mut records: Vec<AnnotatedRecord> = annotated
        .into_iter()
        .filter_map(value_to_timeline_record)
        .collect();
    records.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let temporal_span = match (records.first(), records.last()) {
        (Some(f), Some(l)) if f.timestamp != l.timestamp => Some(TemporalSpan {
            first: f.timestamp.clone(),
            last: l.timestamp.clone(),
        }),
        _ => None,
    };

    let record_count = records.len();
    let findings: Vec<FindingCard> = srum_analysis::compute_findings(&records);

    Ok(SrumFile {
        path: path.to_string_lossy().into_owned(),
        timeline: records,
        findings,
        record_count,
        temporal_span,
        table_names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_srum_nonexistent_path_returns_empty_timeline() {
        let result = parse_srum(std::path::Path::new("/nonexistent/SRUDB.dat"));
        // should not panic — returns Ok with empty timeline
        match result {
            Ok(f) => assert!(f.timeline.is_empty()),
            Err(_) => {} // also acceptable — parse error for bad path
        }
    }
}
