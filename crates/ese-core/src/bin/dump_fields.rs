/// Dump raw tag bytes for the 5 unverified SRUM tables across multiple fixtures.
/// Used to empirically determine KEY_LEN and field offsets for each table.
fn main() {
    use ese_core::EseDatabase;
    use std::path::Path;

    let fixtures = [
        ("chainsaw",        "tests/data/srudb/chainsaw_SRUDB.dat"),
        ("rathbunvm_win10", "tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat"),
        ("rathbunvm_win11", "tests/data/srudb/museum_rathbunvm_win11_SRUDB.dat"),
    ];

    // (label, guid)
    let tables = [
        ("app_usage",     "{5C8CF1C7-7257-4F13-B223-970EF5939312}"),
        ("connectivity",  "{DD6636C4-8929-4683-974E-22C046A43763}"),
        ("energy",        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}"),
        ("push",          "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"),
    ];

    for (flabel, fpath) in &fixtures {
        let db = EseDatabase::open(Path::new(fpath)).expect("open");
        for (tlabel, guid) in &tables {
            let root = match db.find_table_page(guid) {
                Ok(p) => p,
                Err(_) => {
                    println!("[{flabel}][{tlabel}] ABSENT");
                    continue;
                }
            };
            let cursor = db.table_records_from_root(root).expect("cursor");
            let records: Vec<_> = cursor.take(3).collect();
            println!("\n[{flabel}][{tlabel}]");
            for (i, r) in records.iter().enumerate() {
                match r {
                    Ok((page, tag, data)) => {
                        let hex = data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        println!("  rec[{i}] page={page} tag={tag} len={} bytes={}", data.len(), hex);
                    }
                    Err(e) => println!("  rec[{i}] ERR: {e}"),
                }
            }
        }
    }
}
