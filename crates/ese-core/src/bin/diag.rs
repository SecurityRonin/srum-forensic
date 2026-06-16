use ese_core::EseDatabase;
use std::path::Path;

fn main() {
    let path = Path::new("tests/data/srudb/chainsaw_SRUDB.dat");
    let db = EseDatabase::open(path).expect("open");

    for name in &[
        "SruDbIdMapTable",
        "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
        "{5C8CF1C7-7257-4F13-B223-970EF5939312}",
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
    ] {
        match db.find_table_page(name) {
            Ok(root) => {
                let leaves = db.walk_leaf_pages(root).unwrap_or_default();
                let mut total_tags = 0usize;
                for &p in &leaves {
                    if let Ok(page) = db.read_page(p) {
                        if let Ok(tags) = page.tags() {
                            total_tags += tags.len().saturating_sub(1);
                        }
                    }
                }
                println!(
                    "{name}: root={root} leaves={} total_tags={total_tags} pages={:?}",
                    leaves.len(),
                    &leaves[..leaves.len().min(8)]
                );
            }
            Err(e) => println!("{name}: ERR {e}"),
        }
    }
}
