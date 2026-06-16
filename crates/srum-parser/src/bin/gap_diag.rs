fn main() {
    use ese_core::EseDatabase;
    use forensicnomicon::srum::TABLE_APP_RESOURCE_USAGE;

    for (name, fixture) in &[
        ("chainsaw", "tests/data/srudb/chainsaw_SRUDB.dat"),
        (
            "rathbunvm_win10",
            "tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat",
        ),
        (
            "rathbunvm_win11",
            "tests/data/srudb/museum_rathbunvm_win11_SRUDB.dat",
        ),
    ] {
        let path = std::path::Path::new(fixture);
        if !path.exists() {
            println!("{name}: MISSING");
            continue;
        }
        let db = EseDatabase::open(path).expect("open");
        let Ok(cursor) = db.table_records(TABLE_APP_RESOURCE_USAGE) else {
            println!("{name}: table missing");
            continue;
        };

        // Collect record lengths and cb_pfx values to determine COL_DATA_LEN
        // For records where KEY_LEN=16 works (col_start = 2+(16-cb_pfx)), col_data = len - col_start
        let mut len_freq: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
        let mut col_data_samples: Vec<usize> = Vec::new();
        let mut count = 0u64;

        for r in cursor {
            let Ok((_, _, data)) = r else { continue };
            if data.len() < 2 {
                continue;
            }
            let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;
            *len_freq.entry(data.len()).or_insert(0) += 1;
            // Sample col_data assuming KEY_LEN=16 (might be wrong for some)
            if cb_pfx <= 16 {
                let col_start = 2 + (16 - cb_pfx);
                if data.len() > col_start {
                    col_data_samples.push(data.len() - col_start);
                }
            }
            count += 1;
        }
        let most_common_col_data = col_data_samples
            .iter()
            .fold(std::collections::HashMap::new(), |mut m, &v| {
                *m.entry(v).or_insert(0u64) += 1;
                m
            })
            .into_iter()
            .max_by_key(|&(_, cnt)| cnt)
            .map(|(len, _)| len);

        let mut lens: Vec<(usize, u64)> = len_freq.into_iter().collect();
        lens.sort_by_key(|&(_, cnt)| std::cmp::Reverse(cnt));
        let lens_str: Vec<String> = lens
            .iter()
            .take(5)
            .map(|(l, c)| format!("len={l}:{c}"))
            .collect();

        println!(
            "{name}: total={count} most_common_col_data={most_common_col_data:?} len_freq=[{}]",
            lens_str.join(", ")
        );
    }
}
