/// Output format for subcommand results.
#[derive(clap::ValueEnum, Clone, Default, PartialEq)]
pub enum OutputFormat {
    #[default]
    Json,
    Csv,
    Ndjson,
}

/// Render a slice of JSON objects as CSV text.
///
/// Column order follows the key order of the first object.  Missing keys in
/// subsequent rows produce empty cells.
pub fn values_to_csv(values: &[serde_json::Value]) -> anyhow::Result<String> {
    if values.is_empty() {
        return Ok(String::new());
    }
    let headers: Vec<String> = match &values[0] {
        serde_json::Value::Object(m) => m.keys().cloned().collect(),
        _ => anyhow::bail!("expected JSON object for CSV serialisation"),
    };
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&headers)?;
    for v in values {
        if let serde_json::Value::Object(m) = v {
            let row: Vec<String> = headers
                .iter()
                .map(|k| match m.get(k) {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(val) => val.to_string(),
                    None => String::new(),
                })
                .collect();
            wtr.write_record(&row)?;
        }
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}

/// Print `values` in the requested `format`.
pub fn print_values(values: &[serde_json::Value], format: &OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(values)?),
        OutputFormat::Csv => print!("{}", values_to_csv(values)?),
        OutputFormat::Ndjson => {
            for v in values {
                println!("{}", serde_json::to_string(v)?);
            }
        }
    }
    Ok(())
}
