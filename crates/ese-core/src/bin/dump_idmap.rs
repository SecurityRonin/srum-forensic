fn main() {
    use ese_core::EseDatabase;
    use std::path::Path;

    let path = Path::new("../../tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat");
    let db = EseDatabase::open(path).expect("open");

    // Show catalog entries to understand page numbers
    let entries = db.catalog_entries().expect("catalog");
    for e in &entries {
        if e.object_name.contains("SruDbId") || e.object_name.contains("IdMap") {
            println!(
                "catalog: name={:?} type={} page={} obj_id={} parent_id={}",
                e.object_name, e.object_type, e.table_page, e.object_id, e.parent_object_id
            );
        }
    }

    // Try table_records
    match db.table_records("SruDbIdMapTable") {
        Err(e) => println!("ERROR: {e}"),
        Ok(cursor) => {
            let records: Vec<_> = cursor.collect();
            println!("Record count: {}", records.len());
            for (i, r) in records.iter().take(5).enumerate() {
                match r {
                    Ok((page, tag, data)) => {
                        println!(
                            "rec[{i}] page={page} tag={tag} len={} bytes={}",
                            data.len(),
                            data.iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    }
                    Err(e) => println!("rec[{i}] ERROR: {e}"),
                }
            }
        }
    }
}
