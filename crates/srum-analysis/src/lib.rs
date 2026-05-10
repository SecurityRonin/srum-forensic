pub mod analysis;
pub mod enrich;
pub mod findings;
pub mod pipeline;
pub mod record;
pub use record::{AnnotatedRecord, FindingCard, Severity, TemporalSpan};
