extern crate twa_pack_lib;

mod build;

use std::fs::File;
use std::path::Path;

#[test]
fn test_read_header() {
    let f = File::open(Path::new("tests/parse/music.pack")).expect("file not found");
    let pack = twa_pack_lib::parse_pack(f).unwrap();

    for item in pack.into_iter() {
        println!("{}", item);
    }
}
