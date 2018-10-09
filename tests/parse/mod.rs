use fs;
use std::fs::File;
use std::path::Path;

use tw_pack_lib;

#[test]
fn test_read_header() {
    fs::copy("tests/twa_boot.pack.bk", "tests/read_header_twa_boot.pack").unwrap();
    let f = File::open(Path::new("tests/read_header_twa_boot.pack")).expect("file not found");
    let pack = tw_pack_lib::parse_pack(f).unwrap();

    for item in pack.into_iter() {
        println!("{}", item);
        item.get_data().unwrap();
    }
}
