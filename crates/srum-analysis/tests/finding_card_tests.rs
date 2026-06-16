//! SRUM finding cards normalize onto the canonical `forensicnomicon::report`
//! model, mapping the triage vocabulary (Clean/Informational/Suspicious/Critical)
//! onto the 5-level scale.

use forensicnomicon::report::{Severity as Canon, Source};
use srum_analysis::record::{FindingCard, Severity};

#[test]
fn finding_card_converts_to_a_canonical_finding() {
    let card = FindingCard {
        title: "QWCrypt ransomware staging".to_string(),
        app_name: "evil.exe".to_string(),
        description: "high bandwidth to a known C2".to_string(),
        mitre_techniques: vec!["T1486".to_string()],
        severity: Severity::Suspicious,
        filter_flag: "qwcrypt_ransomware".to_string(),
        count: 3,
    };
    let f = card.to_finding(Source {
        analyzer: "srum-forensic".to_string(),
        scope: "SRUM".to_string(),
        version: None,
    });
    assert_eq!(f.code, "SRUM-QWCRYPT-RANSOMWARE");
    assert_eq!(f.severity, Some(Canon::High)); // Suspicious -> High
    assert_eq!(f.context.occurrences.map(std::num::NonZero::get), Some(3));
    assert_eq!(f.context.external_refs[0].id, "T1486");
}
