fn main() {
    use ese_core::EseDatabase;
    use std::path::Path;

    let path = Path::new("../../tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat");
    let db = EseDatabase::open(path).expect("open");

    let guid = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}";
    match db.table_records(guid) {
        Err(e) => println!("ERROR: {e}"),
        Ok(cursor) => {
            let records: Vec<_> = cursor.collect();
            println!("Record count: {}", records.len());
            for (i, r) in records.iter().take(4).enumerate() {
                match r {
                    Ok((page, tag, data)) => {
                        println!("rec[{i}] page={page} tag={tag} len={} bytes={}",
                            data.len(),
                            data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
                    }
                    Err(e) => println!("rec[{i}] ERROR: {e}"),
                }
            }
        }
    }
}
