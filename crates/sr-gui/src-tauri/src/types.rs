use serde::{Deserialize, Serialize};

pub use srum_analysis::record::{AnnotatedRecord, FindingCard, Severity, TemporalSpan};

#[derive(Debug, Serialize, Deserialize)]
pub struct SrumFile {
    pub path: String,
    pub timeline: Vec<AnnotatedRecord>,
    pub findings: Vec<FindingCard>,
    pub record_count: usize,
    pub temporal_span: Option<TemporalSpan>,
    pub table_names: Vec<String>,
}
