fn main() {
    use ese_core::EseDatabase;
    use std::path::Path;
    
    let path = Path::new("tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat");
    let db = EseDatabase::open(path).expect("open");
    let guid = "{5C8CF1C7-7257-4F13-B223-970EF5939312}";

    // Find root and check page structure manually
    let root = db.find_table_page(guid).expect("find table");
    println!("apps root_page={root}");
    
    let page = db.read_page(root).expect("read root");
    let hdr = page.parse_header().expect("hdr");
    println!("root: flags={:#010x} tag_count={}", hdr.page_flags, hdr.available_page_tag_count);
    
    // Check if there are child pages (parent page scenario)
    // In ESE, if a page is ROOT but NOT LEAF, it's a parent pointing to children
    // If tag[1] exists on non-leaf, its last 4 bytes = child page
    // But here page_flags has LEAF bit set... let's ignore LEAF and check for children
    let tags = page.tags().expect("tags");
    println!("Tags on root page: {}", tags.len());
    for (i, (off, sz)) in tags.iter().enumerate() {
        println!("  tag[{i}]: offset={off} size={sz}");
    }
    
    // Also dump raw bytes around the tag area of the root page
    let raw = &page.data[40..40.min(page.data.len().saturating_sub(tags.len()*4))];
    println!("\nData area (bytes 40-80): {:?}", &page.data[40..80.min(page.data.len())].iter().map(|b| format!("{:02x}",b)).collect::<Vec<_>>().join(" "));
}
