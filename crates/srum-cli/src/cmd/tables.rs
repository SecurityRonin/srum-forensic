use std::path::Path;

use crate::output::{OutputFormat, print_values};

pub fn run_network(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let records = srum_parser::parse_network_usage(path)?;
    let values: Vec<serde_json::Value> = if resolve {
        let id_map = srum_analysis::load_id_map(path);
        records.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect()
    } else {
        srum_analysis::records_to_values(records)?
    };
    print_values(&values, format)
}

pub fn run_apps(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let records = srum_parser::parse_app_usage(path)?;
    let mut values: Vec<serde_json::Value> = if resolve {
        let id_map = srum_analysis::load_id_map(path);
        records.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect()
    } else {
        srum_analysis::records_to_values(records)?
    };
    // Inject source_table before merging focus so pipeline can identify rows correctly.
    for v in &mut values {
        if let Some(obj) = v.as_object_mut() {
            obj.insert(
                srum_analysis::pipeline::TABLE_KEY.to_owned(),
                "apps".into(),
            );
        }
    }
    let focus_values: Vec<serde_json::Value> = srum_parser::parse_app_timeline(path)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();
    srum_analysis::pipeline::merge_focus_into_apps(&mut values, focus_values);
    print_values(&values, format)
}

pub fn run_idmap(path: &Path, format: &OutputFormat) -> anyhow::Result<()> {
    let entries = srum_parser::parse_id_map(path)?;
    let values = srum_analysis::records_to_values(entries)?;
    print_values(&values, format)
}

pub fn run_connectivity(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let records = srum_parser::parse_network_connectivity(path)?;
    let mut values = srum_analysis::records_to_values(records)?;
    if resolve {
        let id_map = srum_analysis::load_id_map(path);
        values = values
            .into_iter()
            .map(|r| srum_analysis::enrich_connectivity(r, &id_map))
            .collect();
    }
    print_values(&values, format)
}

pub fn run_energy(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let records = srum_parser::parse_energy_usage(path)?;
    let mut values = srum_analysis::records_to_values(records)?;
    if resolve {
        let id_map = srum_analysis::load_id_map(path);
        values = values.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect();
    }
    print_values(&values, format)
}

pub fn run_energy_lt(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let records = srum_parser::parse_energy_lt(path)?;
    let mut values = srum_analysis::records_to_values(records)?;
    if resolve {
        let id_map = srum_analysis::load_id_map(path);
        values = values.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect();
    }
    print_values(&values, format)
}

pub fn run_notifications(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let records = srum_parser::parse_push_notifications(path)?;
    let mut values = srum_analysis::records_to_values(records)?;
    if resolve {
        let id_map = srum_analysis::load_id_map(path);
        values = values.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect();
    }
    print_values(&values, format)
}

pub fn run_app_timeline(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let records = srum_parser::parse_app_timeline(path)?;
    let values: Vec<serde_json::Value> = if resolve {
        let id_map = srum_analysis::load_id_map(path);
        records.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect()
    } else {
        srum_analysis::records_to_values(records)?
    };
    print_values(&values, format)
}
